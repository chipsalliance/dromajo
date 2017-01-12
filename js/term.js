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

function Term(width, height, handler)
{
    this.w = width;
    this.h = height;

    this.cur_h = height; /* current height of the scroll back buffer */
    this.tot_h = 1000; /* total height of the scroll back buffer */
    this.y_base = 0; /* position of the current top screen line in the
                      * scroll back buffer */
    this.y_disp = 0; /* position of the top displayed line in the
                      * scroll back buffer */
    /* cursor position */
    this.x = 0;
    this.y = 0;
    this.cursorstate = 0;
    this.handler = handler;
    this.convert_lf_to_crlf = false;
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

Term.prototype.open = function()
{
    var y, line, i, term, c;

    /* set initial content */
    this.lines = new Array();
    c = 32 | (this.def_attr << 16);
    for(y = 0; y < this.cur_h;y++) {
        line = new Array();
        for(i=0;i<this.w;i++)
            line[i] = c;
        this.lines[y] = line;
    }

    /* create terminal window */
    document.writeln('<table border="0" cellspacing="0" cellpadding="0">');
    for(y=0;y<this.h;y++) {
        document.writeln('<tr><td class="term" id="tline' + y + '"></td></tr>');
    }
    document.writeln('</table>');
    
    this.refresh(0, this.h - 1);
    
    // key handler
    document.addEventListener("keydown", 
                              this.keyDownHandler.bind(this), true);
    document.addEventListener("keypress", 
                              this.keyPressHandler.bind(this), true);

    // cursor blinking
    term = this;
    setInterval(function() { term.cursor_timer_cb(); }, 1000);
};

Term.prototype.refresh = function(ymin, ymax)
{
    var el, y, line, outline, c, w, i, cx, attr, last_attr, fg, bg, y1;

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
        for(i = 0; i < w; i++) {
            c = line[i];
            attr = c >> 16;
            c &= 0xffff;
            if (i == cx)  {
                attr = -1; /* cursor */
            }
            if (attr != last_attr) {
                if (last_attr != this.def_attr)
                    outline += '</span>';
                if (attr != this.def_attr) {
                    if (attr == -1) {
                        /* cursor */
                        outline += '<span class="termReverse">';
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
        }
        if (last_attr != this.def_attr) {
                    outline += '</span>';
        }

        el = document.getElementById("tline" + y);
        el.innerHTML = outline;
    }
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
        var j, n;

        if (esc_params.length == 0) {
            s.cur_attr= s.def_attr;
        } else {
            for(j = 0; j < esc_params.length; j++) {
                n = esc_params[j];
                if (n >= 30 && n <= 37) {
                    /* foreground */
                    s.cur_attr = (s.cur_attr & ~(7 << 3)) | ((n - 30) << 3);
                } else if (n >= 40 && n <= 47) {
                    /* background */
                    s.cur_attr = (s.cur_attr & ~7) | (n - 40);
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
                if (this.convert_lf_to_crlf) {
                    this.x = 0; // emulates '\r'
                }
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
            if (c == 91) { // '['
                this.esc_params = new Array();
                this.cur_param = 0;
                this.state = TTY_STATE_CSI;
            } else {
                this.state = TTY_STATE_NORM;
            }
            break;
        case TTY_STATE_CSI:
            if (c >= 48 && c <= 57) { // '0' '9'
                /* numeric */
                this.cur_param = this.cur_param * 10 + c - 48;
            } else {
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

