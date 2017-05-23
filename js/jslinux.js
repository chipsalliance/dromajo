/*
 * JS Linux main
 * 
 * Copyright (c) 2017 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
"use strict";

var term, console_write1;
var fs_import_file;
var Module = {};

function on_update_file(f)
{
    var f, reader;
    reader = new FileReader();
    reader.onload = function (ev) {
        var buf, buf_addr, buf_len;
        buf = new Uint8Array(reader.result);
        buf_len = buf.length;
        buf_addr = _malloc(buf_len);
        HEAPU8.set(buf, buf_addr);
        /* the buffer is freed by the function */
        fs_import_file(f.name, buf_addr, buf_len);
    };
    reader.readAsArrayBuffer(f);
}

function on_update_files(files)
{
    var i, n;
    n = files.length;
    for(i = 0; i < n; i++) {
        on_update_file(files[i]);
    }
}

function term_handler(str)
{
    var i;
    for(i = 0; i < str.length; i++) {
        console_write1(str.charCodeAt(i));
    }
}

(function() {
    var url, vm_url, cmdline, mem_size;

    function loadScript(src, f) {
        var head = document.getElementsByTagName("head")[0];
        var script = document.createElement("script");
        script.src = src;
        var done = false;
        script.onload = script.onreadystatechange = function() { 
            // attach to both events for cross browser finish detection:
            if ( !done && (!this.readyState ||
                           this.readyState == "loaded" || this.readyState == "complete") ) {
                done = true;
                f();
                script.onload = script.onreadystatechange = null;
                head.removeChild(script);
            }
        };
        head.appendChild(script);
    }

    function start()
    {
        /* C functions called from javascript */
        console_write1 = cwrap('console_queue_char', null, ['number']);
        fs_import_file = cwrap('fs_import_file', null, ['string', 'number', 'number']);
        Module.ccall("vm_start", null, ["string", "number", "string"], [url, mem_size, cmdline]);
    }
    
    /* start the terminal */

    term = new Term(80, 30, term_handler);
    term.open(document.getElementById("term_container"),
              document.getElementById("term_paste"));
    term.write("Loading...\r\n");

    cmdline = ""; /* kernel command line */
    mem_size = 128; /* memory size in MB */
    
    vm_url = "riscvemu64.js";
    /* change it depending on the location of the files */
    url = "http://localhost/u/os/riscv-poky";
    
    /* set the total memory */
    Module.TOTAL_MEMORY = (mem_size + 64) << 20;

    loadScript(vm_url, start);
})();
