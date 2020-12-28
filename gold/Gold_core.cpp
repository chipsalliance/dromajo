
#include "Gold_core.hpp"

#include "Gold_notify.hpp"

Inst_id Gold_core::global_instid;

Gold_core::Gold_core(Gold_mem &m, int id) : mem(m), cid(id) {}

Inst_id Gold_core::inorder() {
    global_instid = global_instid + 1;
    auto i        = global_instid;

    rob.push_front({i});

    assert(rob.front().rid == i);
    assert(rob.front().op == Mem_op::Invalid);

    return i;
}

void Gold_core::set_type(Inst_id iid, Mem_op op) {
    auto it = std::find_if(rob.begin(), rob.end(), [&iid](const Rob_entry &x) { return x.rid == iid; });

    if (it == rob.end()) {
        return;  // may be nuked
    }

    it->op        = op;
    it->performed = false;
}

void Gold_core::set_safe(Inst_id iid) {
    if (iid >= pnr)
        pnr = iid;
}

void Gold_core::nuke(Inst_id iid) {
    if (iid < pnr) {
        dump();
        Gold_nofity::fail("nuke id:{} for already safe pnr:{}", iid, pnr);
        return;
    }

    if (rob.empty())
        return;

    while (rob.front().rid >= iid) {
        const auto &e = rob.front();
        std::cout << "nuke: rid:" << e.rid << " error:" << e.error << "\n";
        e.dump("rob");

        rob.pop_front();
        if (rob.empty())
            return;
    }
}

Gold_core::Rob_entry &Gold_core::find_entry(Inst_id iid) {
    auto rob_it = std::find_if(rob.begin(), rob.end(), [&iid](const Rob_entry &x) { return x.rid == iid; });

    if (rob_it == rob.end()) {
        dump();
        std::cout << "WARNING: iid:" << iid << " must be in ROB\n";
        static Rob_entry inv(0);
        return inv;
    }

    return *rob_it;
}

Gold_data &Gold_core::ld_data_ref(Inst_id iid) { return find_entry(iid).ld_data; }

Gold_data &Gold_core::st_data_ref(Inst_id iid) { return find_entry(iid).st_data; }

const Gold_data &Gold_core::ld_perform(Inst_id iid) {
    auto &ent = find_entry(iid);

    if (!ent.ld_data.has_data()) {
        std::cout << "ERROR: ld iid:" << iid << " must have address before perform\n";
        ent.dump("ld_perform");
        return ent.ld_data;
    }

    mem.ld_perform(ent.ld_data);

    if (rob.back().rid != iid) {  // Not if load is the oldest in ROB

        Rob_queue::reverse_iterator rob_end
            = std::find_if(rob.rbegin(), rob.rend(), [&iid](const Rob_entry &x) { return x.rid == iid; });
        assert(rob_end != rob.rend());

        for (auto it = rob.rbegin(); it != rob_end; ++it) {
            assert(it->rid < iid);
            if (it->st_data.has_data()) {
                Gold_nofity::info("ld iid:{} fwd from st iid:{}", iid, it->rid);
                ent.ld_data.update_newer(it->st_data);
            }
        }
    }

    ent.performed = true;
    ent.error.clear();

    Gold_nofity::trace(iid, "core:{} ld gp{}", cid, ent.ld_data.str());

    return ent.ld_data;
}

void Gold_core::st_locally_perform(Inst_id iid) {
    auto &ent = find_entry(iid);

    if (!ent.st_data.has_data()) {
        dump();
        std::cout << "ERROR: st iid:" << iid << " must have address before perform\n";
        ent.dump("st_perform");
        return;
    }
    ent.performed = true;

    Rob_queue::reverse_iterator rob_it;
    rob_it = std::find_if(rob.rbegin(), rob.rend(), [&iid](const Rob_entry &x) { return x.rid == iid; });

    Gold_nofity::trace(iid, "core:{} st lp{}", cid, rob_it->st_data.str());

    ++rob_it;  // Skip itself

    for (; rob_it != rob.rend(); ++rob_it) {
        if (!rob_it->ld_data.has_data())
            continue;
        if (!rob_it->performed)
            continue;

        auto ld_data_copy = ld_perform(rob_it->rid);  // perform again
        if (ld_data_copy != rob_it->ld_data) {
            std::cout << "WARNING: ld id:" << rob_it->rid << " performed but data chanced\n";
            rob_it->error = "store id:" + std::to_string(iid) + " changed value";
            ld_data_copy.dump();
            rob_it->dump("after");
        }
    }
}

void Gold_core::st_locally_merged(Inst_id iid1, Inst_id iid2) {
    if (iid1 > iid2) {  // swap, so that iid1 is older
        auto tmp = iid1;
        iid1     = iid2;
        iid2     = tmp;
    }

    auto rob_it1 = std::find_if(rob.begin(), rob.end(), [&iid1](const Rob_entry &x) { return x.rid == iid1; });
    auto rob_it2 = std::find_if(rob.begin(), rob.end(), [&iid2](const Rob_entry &x) { return x.rid == iid2; });

    if (rob_it1 == rob.end() || rob_it2 == rob.end()) {
        dump();
        std::cout << "ERROR: locally merge has missign ids iid1:" << iid1 << " iid2:" << iid2 << "\n";
    }

    // Merge iid2 (younger) to iid1 (older)
    // No store between iid2 and iid1 sould overlap in address with iid2

    auto &d2 = find_entry(iid2);

    ++rob_it2;  // skip itself

    for (; rob_it2 != rob.end(); ++rob_it2) {
        if (rob_it2->rid < iid1)
            return;  // done

        if (rob_it2->rid == iid1) {
            assert(rob_it2 == rob_it1);
            rob_it1->st_merge(d2);
            return;
        }
        if (rob_it2->ld_data.has_partial_overlap(d2.st_data) && !rob_it2->performed) {
            std::cout << "FAIL: between st id:" << iid2 << "and id:" << iid1
                      << " there is a still not performed with partial overlap ld id:" << rob_it2->rid << "\n";
            d2.dump("merged");
            rob_it2->dump("match");
        }

        if (!rob_it2->st_data.has_partial_overlap(d2.st_data))
            continue;

        std::cout << "WARNING: between st id:" << iid2 << "and id:" << iid1 << " there is a partial overlap st id:" << rob_it2->rid
                  << "\n";
        d2.dump("merged");
        rob_it2->dump("match");
    }
}

void Gold_core::st_globally_perform(Inst_id iid) {
    auto rob_it1 = std::find_if(rob.begin(), rob.end(), [&iid](const Rob_entry &x) { return x.rid == iid; });

    if (rob_it1 == rob.end()) {
        dump();
        std::cout << "WARNING: globally perform st id:" << iid << " but id is gone. Nothing to do???\n";
        return;
    }

    if (iid < pnr) {
        dump();
        std::cout << "FAIL: globally perform st id:" << iid << " but NOT safe?? (doing it, but crazy)\n";
    }

    // Check that there are no overlapping older stores

    auto it = rob_it1;
    ++it;  // skip itself

    bool only_reads = true;
    for (; it != rob.end(); ++it) {
        if (it->st_data.has_data())
            only_reads = false;

        if (it->st_data.has_partial_overlap(rob_it1->st_data)) {
            std::cout << "WARNING: older than st id:" << iid << " there is a partial overlap id:" << it->rid << "\n";
            rob_it1->dump("performed");
            it->dump("older");
        }
    }

    st_locally_perform(iid);  // even if performed, we can check again (just in
                              // case missing API call)

    Gold_nofity::trace(iid, "core:{} st gp{}", cid, rob_it1->st_data.str());

    mem.st_perform(rob_it1->st_data);

    if (only_reads) {  // try to retire these
        bool notified = false;

        while (rob.back().rid != iid) {
            auto &oldest = rob.back();

            if (!notified && (!oldest.error.empty() || !oldest.performed)) {
                notified = true;
                std::cout << "FAIL: ld:" << oldest.rid << " is oldest with error:" << oldest.error << "\n";
                dump();
            }

            rob.pop_back();
        }
        assert(rob.back().rid == iid);
        rob.pop_back();
    } else {
        rob.erase(rob_it1);
    }

    // Check that itself got deleted
    assert(std::find_if(rob.begin(), rob.end(), [&iid](const Rob_entry &x) { return x.rid == iid; }) == rob.end());
}

bool Gold_core::has_error(Inst_id iid) const {
    auto it = std::find_if(rob.begin(), rob.end(), [&iid](const Rob_entry &x) { return x.rid == iid; });

    if (it == rob.end())
        return true;

    return !it->error.empty();
}

void Gold_core::dump() const {
    std::cout << "==================================================\n";
    std::cout << "core cid:" << cid << " pnr:" << pnr << "\n";

    for (auto it = rob.rbegin(); it != rob.rend(); ++it) {
        it->dump("rob");
    }
}
