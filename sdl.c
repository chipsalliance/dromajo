/*
 * SDL display driver
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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>

#include <SDL/SDL.h>

#include "cutils.h"
#include "virtio.h"
#include "machine.h"

#define KEYCODE_MAX 127

static SDL_Surface *screen;
static SDL_Surface *fb_surface;
static int screen_width, screen_height, fb_width, fb_height, fb_stride;
static SDL_Cursor *sdl_cursor_hidden;
static uint8_t key_pressed[KEYCODE_MAX + 1];

static void sdl_update_fb_surface(FBDevice *fb_dev)
{
    if (!fb_surface)
        goto force_alloc;
    if (fb_width != fb_dev->width ||
        fb_height != fb_dev->height ||
        fb_stride != fb_dev->stride) {
    force_alloc:
        if (fb_surface != NULL)
            SDL_FreeSurface(fb_surface);
        fb_width = fb_dev->width;
        fb_height = fb_dev->height;
        fb_stride = fb_dev->stride;
        fb_surface = SDL_CreateRGBSurfaceFrom(fb_dev->fb_data,
                                              fb_dev->width, fb_dev->height,
                                              32, fb_dev->stride,
                                              0x00ff0000,
                                              0x0000ff00,
                                              0x000000ff,
                                              0x00000000);
        if (!fb_surface) {
            fprintf(stderr, "Could not create SDL framebuffer surface\n");
            exit(1);
        }
    }
}

static void sdl_update(FBDevice *fb_dev, void *opaque,
                       int x, int y, int w, int h)
{
    SDL_Rect r;
    //    printf("sdl_update: %d %d %d %d\n", x, y, w, h);
    r.x = x;
    r.y = y;
    r.w = w;
    r.h = h;
    SDL_BlitSurface(fb_surface, &r, screen, &r);
    SDL_UpdateRect(screen, r.x, r.y, r.w, r.h);
}

#if defined(_WIN32)

static int sdl_get_keycode(const SDL_KeyboardEvent *ev)
{
    return ev->keysym.scancode;
}

#else

/* we assume Xorg is used with a PC keyboard. Return 0 if no keycode found. */
static int sdl_get_keycode(const SDL_KeyboardEvent *ev)
{
    int keycode;
    keycode = ev->keysym.scancode;
    if (keycode < 9) {
        keycode = 0;
    } else if (keycode < 127 + 8) {
        keycode -= 8;
    } else {
        keycode = 0;
    }
    return keycode;
}

#endif

/* release all pressed keys */
static void sdl_reset_keys(VirtMachine *m)
{
    int i;
    
    for(i = 1; i <= KEYCODE_MAX; i++) {
        if (key_pressed[i]) {
            vm_send_key_event(m, FALSE, i);
            key_pressed[i] = FALSE;
        }
    }
}

static void sdl_handle_key_event(const SDL_KeyboardEvent *ev, VirtMachine *m)
{
    int keycode, keypress;

    keycode = sdl_get_keycode(ev);
    if (keycode) {
        if (keycode == 0x3a || keycode ==0x45) {
            /* SDL does not generate key up for numlock & caps lock */
            vm_send_key_event(m, TRUE, keycode);
            vm_send_key_event(m, FALSE, keycode);
        } else {
            keypress = (ev->type == SDL_KEYDOWN);
            if (keycode <= KEYCODE_MAX)
                key_pressed[keycode] = keypress;
            vm_send_key_event(m, keypress, keycode);
        }
    } else if (ev->type == SDL_KEYUP) {
        /* workaround to reset the keyboard state (used when changing
           desktop with ctrl-alt-x on Linux) */
        sdl_reset_keys(m);
    }
}

static void sdl_send_mouse_event(VirtMachine *m, int x1, int y1,
                                 int dz, int state, BOOL is_absolute)
{
    int buttons, x, y;

    buttons = 0;
    if (state & SDL_BUTTON(SDL_BUTTON_LEFT))
        buttons |= (1 << 0);
    if (state & SDL_BUTTON(SDL_BUTTON_RIGHT))
        buttons |= (1 << 1);
    if (state & SDL_BUTTON(SDL_BUTTON_MIDDLE))
        buttons |= (1 << 2);
    if (is_absolute) {
        x = (x1 * 32768) / screen_width;
        y = (y1 * 32768) / screen_height;
    } else {
        x = x1;
        y = y1;
    }
    vm_send_mouse_event(m, x, y, dz, buttons);
}

static void sdl_handle_mouse_motion_event(const SDL_Event *ev, VirtMachine *m)
{
    BOOL is_absolute = vm_mouse_is_absolute(m);
    int x, y;
    if (is_absolute) {
        x = ev->motion.x;
        y = ev->motion.y;
    } else {
        x = ev->motion.xrel;
        y = ev->motion.yrel;
    }
    sdl_send_mouse_event(m, x, y, 0, ev->motion.state, is_absolute);
}

static void sdl_handle_mouse_button_event(const SDL_Event *ev, VirtMachine *m)
{
    BOOL is_absolute = vm_mouse_is_absolute(m);
    int state, dz;

    dz = 0;
    if (ev->type == SDL_MOUSEBUTTONDOWN) {
        if (ev->button.button == SDL_BUTTON_WHEELUP) {
            dz = 1;
        } else if (ev->button.button == SDL_BUTTON_WHEELDOWN) {
            dz = -1;
        }
    }
    
    state = SDL_GetMouseState(NULL, NULL);
    /* just in case */
    if (ev->type == SDL_MOUSEBUTTONDOWN)
        state |= SDL_BUTTON(ev->button.button);
    else
        state &= ~SDL_BUTTON(ev->button.button);

    if (is_absolute) {
        sdl_send_mouse_event(m, ev->button.x, ev->button.y,
                             dz, state, is_absolute);
    } else {
        sdl_send_mouse_event(m, 0, 0, dz, state, is_absolute);
    }
}

void sdl_refresh(VirtMachine *m)
{
    SDL_Event ev_s, *ev = &ev_s;

    if (!m->fb_dev)
        return;
    
    sdl_update_fb_surface(m->fb_dev);

    m->fb_dev->refresh(m->fb_dev, sdl_update, NULL);
    
    while (SDL_PollEvent(ev)) {
        switch (ev->type) {
        case SDL_KEYDOWN:
        case SDL_KEYUP:
            sdl_handle_key_event(&ev->key, m);
            break;
        case SDL_MOUSEMOTION:
            sdl_handle_mouse_motion_event(ev, m);
            break;
        case SDL_MOUSEBUTTONDOWN:
        case SDL_MOUSEBUTTONUP:
            sdl_handle_mouse_button_event(ev, m);
            break;
        case SDL_QUIT:
            exit(0);
        }
    }
}

static void sdl_hide_cursor(void)
{
    uint8_t data = 0;
    sdl_cursor_hidden = SDL_CreateCursor(&data, &data, 8, 1, 0, 0);
    SDL_ShowCursor(1);
    SDL_SetCursor(sdl_cursor_hidden);
}

void sdl_init(int width, int height)
{
    int flags;
    
    screen_width = width;
    screen_height = height;

    if (SDL_Init (SDL_INIT_VIDEO | SDL_INIT_NOPARACHUTE)) {
        fprintf(stderr, "Could not initialize SDL - exiting\n");
        exit(1);
    }

    flags = SDL_HWSURFACE | SDL_ASYNCBLIT | SDL_HWACCEL;
    screen = SDL_SetVideoMode(width, height, 0, flags);
    if (!screen || !screen->pixels) {
        fprintf(stderr, "Could not open SDL display\n");
        exit(1);
    }

    SDL_WM_SetCaption("TinyEMU", "TinyEMU");

    sdl_hide_cursor();
}

