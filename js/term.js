/*
 * Javascript terminal
 * 
 * Copyright (c) 2011 Fabrice Bellard
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

function Term(width, height, handler, tot_height)
{
    this.w = width;
    this.h = height;

    this.cur_h = height; /* current height of the scroll back buffer */
    if (!tot_height || tot_height < height)
        tot_height = height;
    this.tot_h = tot_height; /* maximum height of the scroll back buffer */
    this.y_base = 0; /* position of the current top screen line in the
                      * scroll back buffer */
    this.y_disp = 0; /* position of the top displayed line in the
                      * scroll back buffer */
    /* cursor position */
    this.x = 0;
    this.y = 0;
    this.cursorstate = 0;
    this.handler = handler;
    this.state = 0;
    this.output_queue = "";
    this.bg_colors = [
        "#000000",
        "#ff0000",
        "#00ff00",
        "#ffff00",
        "#0000ff",
        "#ff00ff",
        "#00ffff",
        "#ffffff" 
    ];
    this.fg_colors = [
        "#000000",
        "#ff0000",
        "#00ff00",
        "#ffff00",
        "#0000ff",
        "#ff00ff",
        "#00ffff",
        "#ffffff" 
    ];
    this.def_attr = (7 << 3) | 0;
    this.cur_attr = this.def_attr;
    this.is_mac = (navigator.userAgent.indexOf("Mac") >=0 ) ? true : false;
    this.key_rep_state = 0;
    this.key_rep_str = "";
}

Term.prototype.open = function(parent_el, textarea_el)
{
    var y, line, i, term, c, row_el;

    /* set initial content */
    this.lines = new Array();
    c = 32 | (this.def_attr << 16);
    for(y = 0; y < this.cur_h;y++) {
        line = new Array();
        for(i=0;i<this.w;i++)
            line[i] = c;
        this.lines[y] = line;
    }

    /* create the terminal window */
    this.term_el = document.createElement("div");
    this.term_el.className = "term";
    this.term_el.style.lineHeight = "1.2em";
    /* XXX: could compute the font metrics */
    this.term_el.style.width = "calc(" + this.w + "ch + 16px)";
    this.term_el.style.height = (this.h * 1.2) + "em";
    
    /* scroll bar */
    this.scrollbar_el = document.createElement("div");
    this.scrollbar_el.className = "term_scrollbar";
    this.term_el.appendChild(this.scrollbar_el);

    this.track_el = document.createElement("div");
    this.track_el.className = "term_track";
    this.track_el.onmousedown = this.mouseMoveHandler.bind(this);
    this.scrollbar_el.appendChild(this.track_el);
    
    this.thumb_el = document.createElement("div");
    this.thumb_el.className = "term_thumb";
    this.thumb_el.onmousedown = this.mouseDownHandler.bind(this);
    this.track_el.appendChild(this.thumb_el);

    this.end_el = document.createElement("div");
    this.end_el.className = "term_end";
    this.thumb_el.appendChild(this.end_el);

    /* current scrollbar position */
    this.thumb_size = -1;
    this.thumb_pos = -1;
    
    /* terminal content */
    this.content_el = document.createElement("div");
    this.content_el.className = "term_content";
    this.content_el.style.width = (this.w) + "ch";
    this.term_el.appendChild(this.content_el);
    
    this.rows_el = [];
    for(y=0;y<this.h;y++) {
        row_el = document.createElement("div");
        this.rows_el.push(row_el);
        this.content_el.appendChild(row_el);
    }
    
    this.parent_el = parent_el;
    parent_el.appendChild(this.term_el);

    /* dummy text area for copy paste & mobile devices */
    this.textarea_el = textarea_el;

    this.refresh(0, this.h - 1);
    
    // key handler
    document.addEventListener("keydown", 
                              this.keyDownHandler.bind(this), true);
    document.addEventListener("keypress", 
                              this.keyPressHandler.bind(this), true);
    // wheel
    document.addEventListener("wheel", 
                              this.wheelHandler.bind(this), false);
    // paste
    document.defaultView.addEventListener("paste", 
                                          this.pasteHandler.bind(this), false);
    
    // cursor blinking
    term = this;
    setInterval(function() { term.cursor_timer_cb(); }, 1000);
};

Term.prototype.refresh_scrollbar = function ()
{
    var total_size, thumb_pos, thumb_size, y, y0;
    total_size = this.term_el.clientHeight;
    thumb_size = Math.ceil(this.h * total_size / this.cur_h);
    /* position of the first line of the scroll back buffer */
    y0 = (this.y_base + this.h) % this.cur_h;
    y = this.y_disp - y0;
    if (y < 0)
        y += this.cur_h;
    thumb_pos = Math.floor(y * total_size / this.cur_h);
    thumb_size = Math.max(thumb_size, 30);
    thumb_size = Math.min(thumb_size, total_size);
    thumb_pos = Math.min(thumb_pos, total_size - thumb_size);
//    console.log("pos=" + thumb_pos + " size=" + thumb_size);
    if (thumb_pos != this.thumb_pos || thumb_size != this.thumb_size) {
        this.thumb_pos = thumb_pos;
        this.thumb_size = thumb_size;
        this.thumb_el.style.top = thumb_pos + "px";
        this.thumb_el.style.height = thumb_size + "px";
    }
}

Term.prototype.refresh = function(ymin, ymax)
{
    var el, y, line, outline, c, w, i, j, cx, attr, last_attr, fg, bg, y1;
    var http_link_len, http_link_str;
    
    function is_http_link_char(c)
    {
        var str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=`.";
        return str.indexOf(String.fromCharCode(c)) >= 0;
    }

    function right_trim(str, a)
    {
        var i, n;
        n = a.length;
        i = str.length;
        while (i >= n && str.substr(i - n, n) == a)
            i -= n;
        return str.substr(0, i);
    }
    
    for(y = ymin; y <= ymax; y++) {
        /* convert to HTML string */
        y1 = y + this.y_disp;
        if (y1 >= this.cur_h)
            y1 -= this.cur_h;
        line = this.lines[y1];
        outline = "";
        w = this.w;
        if (y == this.y && this.cursor_state && 
            this.y_disp == this.y_base) {
            cx = this.x;
        } else {
            cx = -1;
        }
        last_attr = this.def_attr;
        http_link_len = 0;
        for(i = 0; i < w; i++) {
            c = line[i];
            attr = c >> 16;
            c &= 0xffff;
            /* test for http link */
            if (c == 0x68 && (w - i) >= 8 && http_link_len == 0) {
                /* test http:// or https:// */
                if ((line[i + 1] & 0xffff) == 0x74 &&
                    (line[i + 2] & 0xffff) == 0x74 &&
                    (line[i + 3] & 0xffff) == 0x70 &&
                    (((line[i + 4] & 0xffff) == 0x3a &&
                      (line[i + 5] & 0xffff) == 0x2f &&
                      (line[i + 6] & 0xffff) == 0x2f) ||
                     ((line[i + 4] & 0xffff) == 0x73 &&
                      (line[i + 5] & 0xffff) == 0x3a &&
                      (line[i + 6] & 0xffff) == 0x2f &&
                      (line[i + 7] & 0xffff) == 0x2f))) {
                    http_link_str = "";
                    j = 0;
                    while ((i + j) < w &&
                           is_http_link_char(line[i + j] & 0xffff)) {
                        http_link_str += String.fromCharCode(line[i + j] & 0xffff);
                        j++;
                    }
                    http_link_len = j;
                    if (last_attr != this.def_attr) {
                        outline += '</span>';
                        last_attr = this.def_attr;
                    }
                    outline += "<a href='" + http_link_str + "'>";
                }
            }
            if (i == cx)  {
                attr = -1; /* cursor */
            }
            if (attr != last_attr) {
                if (last_attr != this.def_attr)
                    outline += '</span>';
                if (attr != this.def_attr) {
                    if (attr == -1) {
                        /* cursor */
                        outline += '<span class="term_cursor">';
                    } else {
                        outline += '<span style="';
                        fg = (attr >> 3) & 7;
                        bg = attr & 7;
                        if (fg != 7) {
                            outline += 'color:' + this.fg_colors[fg] + ';';
                        }
                        if (bg != 0) {
                            outline += 'background-color:' + 
                                this.bg_colors[bg] + ';';
                        }
                        outline += '">';
                    }
                }
            }
            switch(c) {
            case 32:
                outline += "&nbsp;";
                break;
            case 38: // '&'
                outline += "&amp;";
                break;
            case 60: // '<'
                outline += "&lt;";
                break;
            case 62: // '>'
                outline += "&gt;";
                break;
            default:
                if (c < 32) {
                    outline += "&nbsp;";
                } else {
                    outline += String.fromCharCode(c);
                }
                break;
            }
            last_attr = attr;
            if (http_link_len != 0) {
                http_link_len--;
                if (http_link_len == 0) {
                    if (last_attr != this.def_attr) {
                        outline += '</span>';
                        last_attr = this.def_attr;
                    }
                    outline += "</a>";
                }
            }
        }
        if (last_attr != this.def_attr) {
            outline += '</span>';
        }

        /* trim trailing spaces for copy/paste */
        outline = right_trim(outline, "&nbsp;");
        if (outline == "")
            outline = "&nbsp;";
        
        this.rows_el[y].innerHTML = outline;
    }

    this.refresh_scrollbar();
};

Term.prototype.cursor_timer_cb = function()
{
    this.cursor_state ^= 1;
    this.refresh(this.y, this.y);
};

Term.prototype.show_cursor = function()
{
    if (!this.cursor_state) {
        this.cursor_state = 1;
        this.refresh(this.y, this.y);
    }
};

Term.prototype.scroll = function()
{
    var y, line, x, c, y1;

    /* increase height of buffer if possible */
    if (this.cur_h < this.tot_h) {
        this.cur_h++;
    }
    /* move down one line */
    if (++this.y_base == this.cur_h)
        this.y_base = 0;
    this.y_disp = this.y_base;

    c = 32 | (this.def_attr << 16);
    line = new Array();
    for(x=0;x<this.w;x++)
        line[x] = c;
    y1 = this.y_base + this.h - 1;
    if (y1 >= this.cur_h)
        y1 -= this.cur_h;
    this.lines[y1] = line;
};

/* scroll down or up in the scroll back buffer by n lines */
Term.prototype.scroll_disp = function(n)
{
    var i, y1;
    /* slow but it does not really matters */
    if (n >= 0) {
        for(i = 0; i < n; i++) {
            if (this.y_disp == this.y_base)
                break;
            if (++this.y_disp == this.cur_h)
                this.y_disp = 0;
        }
    } else {
        n = -n;
        y1 = this.y_base + this.h;
        if (y1 >= this.cur_h)
            y1 -= this.cur_h;
        for(i = 0; i < n; i++) {
            if (this.y_disp == y1)
                break;
            if (--this.y_disp < 0)
                this.y_disp = this.cur_h - 1;
        }
    }
    this.refresh(0, this.h - 1);
};

Term.prototype.write = function(str)
{
    function update(y) 
    {
        ymin = Math.min(ymin, y);
        ymax = Math.max(ymax, y);
    }

    function erase_to_eol(s, x, y)
    {
        var l, i, c, y1;
        y1 = s.y_base + y;
        if (y1 >= s.cur_h)
            y1 -= s.cur_h;
        l = s.lines[y1];
        c = 32 | (s.def_attr << 16);
        for(i = x; i < s.w; i++)
            l[i] = c;
        update(y);
    }

    function csi_colors(s, esc_params)
    {
        var j, n, fg, bg;

        if (esc_params.length == 0) {
            s.cur_attr= s.def_attr;
        } else {
            for(j = 0; j < esc_params.length; j++) {
                n = esc_params[j];
                if (n >= 30 && n <= 37) {
                    /* foreground */
                    fg = n - 30;
                    s.cur_attr = (s.cur_attr & ~(7 << 3)) | (fg << 3);
                } else if (n >= 40 && n <= 47) {
                    /* background */
                    bg = n - 40;
                    s.cur_attr = (s.cur_attr & ~7) | bg;
                } else if (n >= 90 && n <= 97) {
                    /* foreground (XXX: 16 color table) */
                    fg = n - 90;
                    s.cur_attr = (s.cur_attr & ~(7 << 3)) | (fg << 3);
                } else if (n >= 100 && n <= 107) {
                    /* background (XXX: 16 color table) */
                    bg = n - 100;
                    s.cur_attr = (s.cur_attr & ~7) | bg;
                } else if (n == 0) {
                    /* default attr */
                    s.cur_attr = s.def_attr;
                }
            }
        }
    }

    var TTY_STATE_NORM = 0;
    var TTY_STATE_ESC = 1;
    var TTY_STATE_CSI = 2;
    var TTY_STATE_CHARSET = 3;

    var i, c, ymin, ymax, l, n, j, y1;

    /* update region is in ymin ymax */
    ymin = this.h;
    ymax = -1;
    update(this.y); // remove the cursor
    /* reset top of displayed screen to top of real screen */
    if (this.y_base != this.y_disp) {
        this.y_disp = this.y_base;
        /* force redraw */
        ymin = 0;
        ymax = this.h - 1;
    }
    for(i = 0; i < str.length; i++) {
        c = str.charCodeAt(i);
        switch(this.state) {
        case TTY_STATE_NORM:
            switch(c) {
            case 10:
                this.y++;
                if (this.y >= this.h) {
                    this.y--;
                    this.scroll();
                    ymin = 0;
                    ymax = this.h - 1;
                }
                break;
            case 13:
                this.x = 0;
                break;
            case 8:
                if (this.x > 0) {
                    this.x--;
                }
                break;
            case 9: /* tab */
                n = (this.x + 8) & ~7;
                if (n <= this.w) {
                    this.x = n;
                }
                break;
            case 27:
                this.state = TTY_STATE_ESC;
                break;
            default:
                if (c >= 32) {
                    if (this.x >= this.w) {
                        this.x = 0;
                        this.y++;
                        if (this.y >= this.h) {
                            this.y--;
                            this.scroll();
                            ymin = 0;
                            ymax = this.h - 1;
                        }
                    }
                    y1 = this.y + this.y_base;
                    if (y1 >= this.cur_h)
                        y1 -= this.cur_h;
                    this.lines[y1][this.x] = (c & 0xffff) | 
                        (this.cur_attr << 16);
                    this.x++;
                    update(this.y);
                }
                break;
            }
            break;
        case TTY_STATE_ESC:
            switch(c) {
            case 91: // '['
                this.esc_params = new Array();
                this.cur_param = 0;
                this.state = TTY_STATE_CSI;
                break;
            case 40: // '('
            case 41: // ')'
                this.state = TTY_STATE_CHARSET;
                break;
            default:
                this.state = TTY_STATE_NORM;
                break;
            }
            break;
        case TTY_STATE_CSI:
            if (c >= 48 && c <= 57) { // '0' '9'
                /* numeric */
                this.cur_param = this.cur_param * 10 + c - 48;
            } else {
                if (c == 63) // '?'
                    break; /* ignore prefix */
                /* add parsed parameter */
                this.esc_params[this.esc_params.length] = this.cur_param;
                this.cur_param = 0;
                if (c == 59) // ;
                    break;
                this.state = TTY_STATE_NORM;

                //                console.log("term: csi=" + this.esc_params + " cmd="+c);
                switch(c) {
                case 65: // 'A' up
                    n = this.esc_params[0];
                    if (n < 1)
                        n = 1;
                    this.y -= n;
                    if (this.y < 0)
                        this.y = 0;
                    break;
                case 66: // 'B' down
                    n = this.esc_params[0];
                    if (n < 1)
                        n = 1;
                    this.y += n;
                    if (this.y >= this.h)
                        this.y = this.h - 1;
                    break;
                case 67: // 'C' right
                    n = this.esc_params[0];
                    if (n < 1)
                        n = 1;
                    this.x += n;
                    if (this.x >= this.w - 1)
                        this.x = this.w - 1;
                    break;
                case 68: // 'D' left
                    n = this.esc_params[0];
                    if (n < 1)
                        n = 1;
                    this.x -= n;
                    if (this.x < 0)
                        this.x = 0;
                    break;

                case 72: // 'H' goto xy
                    {
                        var x1, y1;
                        y1 = this.esc_params[0] - 1;
                        if (this.esc_params.length >= 2)
                            x1 = this.esc_params[1] - 1;
                        else
                            x1 = 0;
                        if (y1 < 0)
                            y1 = 0;
                        else if (y1 >= this.h)
                            y1 = this.h - 1;
                        if (x1 < 0)
                            x1 = 0;
                        else if (x1 >= this.w)
                            x1 = this.w - 1;
                        this.x = x1;
                        this.y = y1;
                    }
                    break;
                case 74: // 'J' erase to end of screen
                    erase_to_eol(this, this.x, this.y);
                    for(j = this.y + 1; j < this.h; j++)
                        erase_to_eol(this, 0, j);
                    break;
                case 75: // 'K' erase to end of line
                    erase_to_eol(this, this.x, this.y);
                    break;
                case 109: // 'm': set color
                    csi_colors(this, this.esc_params);
                    break;
                case 110: // 'n' return the cursor position
                    this.queue_chars("\x1b[" + (this.y + 1) + ";" + (this.x + 1) + "R");
                    break;
                default:
                    break;
                }
            }
            break;
        case TTY_STATE_CHARSET:
            /* just ignore */
            this.state = TTY_STATE_NORM;
            break;
        }
    }
    update(this.y); // show the cursor

    if (ymax >= ymin)
        this.refresh(ymin, ymax);
};

Term.prototype.writeln = function (str)
{
    this.write(str + '\r\n');
};

Term.prototype.keyDownHandler = function (ev)
{
    var str;

    str="";
    switch(ev.keyCode) {
    case 8: /* backspace */
        str = "\x7f";
        break;
    case 9: /* tab */
        str = "\x09";
        break;
    case 13: /* enter */
        str = "\x0d";
        break;
    case 27: /* escape */
        str = "\x1b";
        break;
    case 37: /* left */
        str = "\x1b[D";
        break;
    case 39: /* right */
        str = "\x1b[C";
        break;
    case 38: /* up */
        if (ev.ctrlKey) {
            this.scroll_disp(-1);
        } else {
            str = "\x1b[A";
        }
        break;
    case 40: /* down */
        if (ev.ctrlKey) {
            this.scroll_disp(1);
        } else {
            str = "\x1b[B";
        }
        break;
    case 46: /* delete */
        str = "\x1b[3~";
        break;
    case 45: /* insert */
        str = "\x1b[2~";
        break;
    case 36: /* home */
        str = "\x1bOH";
        break;
    case 35: /* end */
        str = "\x1bOF";
        break;
    case 33: /* page up */
        if (ev.ctrlKey) {
            this.scroll_disp(-(this.h - 1));
        } else {
            str = "\x1b[5~";
        }
        break;
    case 34: /* page down */
        if (ev.ctrlKey) {
            this.scroll_disp(this.h - 1);
        } else {
            str = "\x1b[6~";
        }
        break;
    default:
        if (ev.ctrlKey) {
            /* ctrl + key */
            if (ev.keyCode >= 65 && ev.keyCode <= 90) {
                str = String.fromCharCode(ev.keyCode - 64);
            } else if (ev.keyCode == 32) {
                str = String.fromCharCode(0);
            }
        } else if ((!this.is_mac && ev.altKey) ||
                   (this.is_mac && ev.metaKey)) {
            /* meta + key (Note: we only send lower case) */
            if (ev.keyCode >= 65 && ev.keyCode <= 90) {
                str = "\x1b" + String.fromCharCode(ev.keyCode + 32);
            }
        }
        break;
    }
    //    console.log("keydown: keycode=" + ev.keyCode + " charcode=" + ev.charCode + " str=" + str + " ctrl=" + ev.ctrlKey + " alt=" + ev.altKey + " meta=" + ev.metaKey);
    if (str) {
        if (ev.stopPropagation)
            ev.stopPropagation();
        if (ev.preventDefault)
            ev.preventDefault();

        this.show_cursor();
        this.key_rep_state = 1;
        this.key_rep_str = str;
        this.handler(str);
        return false;
    } else {
        this.key_rep_state = 0;
        return true;
    }
};

Term.prototype.keyPressHandler = function (ev)
{
    var str, char_code;
    
    if (ev.stopPropagation)
        ev.stopPropagation();
    if (ev.preventDefault)
        ev.preventDefault();

    str="";
    if (!("charCode" in ev)) {
        /* on Opera charCode is not defined and keypress is sent for
         system keys. Moreover, only keupress is repeated which is a
         problem for system keys. */
        char_code = ev.keyCode;
        if (this.key_rep_state == 1) {
            this.key_rep_state = 2;
            return false;
        } else if (this.key_rep_state == 2) {
            /* repetition */
            this.show_cursor();
            this.handler(this.key_rep_str);
            return false;
        }
    } else {
        char_code = ev.charCode;
    }
    if (char_code != 0) {
        if (!ev.ctrlKey && 
            ((!this.is_mac && !ev.altKey) ||
             (this.is_mac && !ev.metaKey))) {
            str = String.fromCharCode(char_code);
        }
    }
    //    console.log("keypress: keycode=" + ev.keyCode + " charcode=" + ev.charCode + " str=" + str + " ctrl=" + ev.ctrlKey + " alt=" + ev.altKey + " meta=" + ev.metaKey);
    if (str) {
        this.show_cursor();
        this.handler(str);
        return false;
    } else {
        return true;
    }
};

Term.prototype.wheelHandler = function (ev)
{
    if (ev.deltaY < 0)
        this.scroll_disp(-3);
    else if (ev.deltaY > 0)
        this.scroll_disp(3);
    ev.stopPropagation();
}

Term.prototype.mouseDownHandler = function (ev)
{
    this.thumb_el.onmouseup = this.mouseUpHandler.bind(this);
    document.onmousemove = this.mouseMoveHandler.bind(this);
    document.onmouseup = this.mouseUpHandler.bind(this);

    /* disable potential selection */
    document.body.className += " noSelect";
    
    this.mouseMoveHandler(ev);
}

Term.prototype.mouseMoveHandler = function (ev)
{
    var total_size, pos, new_y_disp, y, y0;
    total_size = this.term_el.clientHeight;
    y = ev.clientY - this.track_el.getBoundingClientRect().top;
    pos = Math.floor((y - (this.thumb_size / 2)) * this.cur_h / total_size);
    new_y_disp = Math.min(Math.max(pos, 0), this.cur_h - this.h);
    /* position of the first line of the scroll back buffer */
    y0 = (this.y_base + this.h) % this.cur_h;
    new_y_disp += y0;
    if (new_y_disp >= this.cur_h)
        new_y_disp -= this.cur_h;
    if (new_y_disp != this.y_disp) {
        this.y_disp = new_y_disp;
        this.refresh(0, this.h - 1);
    }
}

Term.prototype.mouseUpHandler = function (ev)
{
    this.thumb_el.onmouseup = null;
    document.onmouseup = null;
    document.onmousemove = null;
    document.body.className = document.body.className.replace(" noSelect", "");
}

Term.prototype.pasteHandler = function (ev)
{
    var c = ev.clipboardData;
    if (c) {
        this.queue_chars(c.getData("text/plain"));
        setTimeout(this.textAreaReset.bind(this), 10);
        return false;
    }
}

Term.prototype.textAreaReset = function(ev)
{
    /* reset text */
    this.textarea_el.value = "Paste Here";
}

/* output queue to send back asynchronous responses */
Term.prototype.queue_chars = function (str)
{
    this.output_queue += str;
    if (this.output_queue)
        setTimeout(this.outputHandler.bind(this), 0);
};

Term.prototype.outputHandler = function ()
{
    if (this.output_queue) {
        this.handler(this.output_queue);
        this.output_queue = "";
    }
};

Term.prototype.getSize = function ()
{
    return [this.w, this.h];
};
