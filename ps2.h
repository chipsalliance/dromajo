/* ps2.c */
typedef struct PS2MouseState PS2MouseState;
typedef struct PS2KbdState PS2KbdState;

PS2KbdState *ps2_kbd_init(void (*update_irq)(void *, int), void *update_arg);
PS2MouseState *ps2_mouse_init(void (*update_irq)(void *, int), void *update_arg);
void ps2_write_mouse(void *, int val);
void ps2_write_keyboard(void *, int val);
uint32_t ps2_read_data(void *);
void ps2_queue(void *, int b);
void ps2_keyboard_set_translation(void *opaque, int mode);

void ps2_put_keycode(PS2KbdState *s, BOOL is_down, int keycode);
void ps2_mouse_event(PS2MouseState *s,
                     int dx, int dy, int dz, int buttons_state);

/* vmmouse.c */
typedef struct VMMouseState VMMouseState;

VMMouseState *vmmouse_init(PS2MouseState *ps2_mouse);
BOOL vmmouse_is_absolute(VMMouseState *s);
void vmmouse_send_mouse_event(VMMouseState *s, int x, int y, int dz,
                              int buttons);
void vmmouse_handler(VMMouseState *s, uint32_t *regs);

/* pckbd.c */

typedef struct KBDState KBDState;

KBDState *i8042_init(PS2KbdState **pkbd,
                     PS2MouseState **pmouse,
                     PhysMemoryMap *port_map,
                     IRQSignal *kbd_irq, IRQSignal *mouse_irq,
                     uint32_t io_base);
