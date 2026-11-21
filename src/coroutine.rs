/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Stackful coroutines.
//!
//! corosensei is used natively. It has no WebAssembly backend, so on
//! Emscripten a minimal API-compatible replacement is built on Emscripten's
//! fibers (which require linking with `-sASYNCIFY`).

#[cfg(not(target_os = "emscripten"))]
pub use corosensei::{Coroutine, CoroutineResult, Yielder};

#[cfg(target_os = "emscripten")]
pub use self::fiber::{Coroutine, CoroutineResult, Yielder};

#[cfg(target_os = "emscripten")]
mod fiber {
    use std::cell::UnsafeCell;
    use std::ffi::c_void;

    /// Storage for `emscripten_fiber_t`, which is 32 bytes on wasm32.
    #[repr(C, align(16))]
    struct FiberT([u8; 64]);

    extern "C" {
        fn emscripten_fiber_init(
            fiber: *mut FiberT,
            entry_func: extern "C" fn(*mut c_void),
            entry_func_arg: *mut c_void,
            c_stack: *mut c_void,
            c_stack_size: usize,
            asyncify_stack: *mut c_void,
            asyncify_stack_size: usize,
        );
        fn emscripten_fiber_init_from_current_context(
            fiber: *mut FiberT,
            asyncify_stack: *mut c_void,
            asyncify_stack_size: usize,
        );
        fn emscripten_fiber_swap(old_fiber: *mut FiberT, new_fiber: *mut FiberT);
    }

    const C_STACK_SIZE: usize = 1024 * 1024;
    const ASYNCIFY_STACK_SIZE: usize = 1024 * 1024;

    pub enum CoroutineResult<Y, R> {
        Yield(Y),
        Return(R),
    }

    /// Handle passed to the coroutine body for suspending itself.
    pub struct Yielder<I, Y> {
        caller: UnsafeCell<FiberT>,
        callee: UnsafeCell<FiberT>,
        caller_asyncify_stack: UnsafeCell<Vec<u8>>,
        input: UnsafeCell<Option<I>>,
        yielded: UnsafeCell<Option<Y>>,
    }

    impl<I, Y> Yielder<I, Y> {
        pub fn suspend(&self, val: Y) -> I {
            unsafe {
                *self.yielded.get() = Some(val);
                emscripten_fiber_swap(self.callee.get(), self.caller.get());
                (*self.input.get()).take().unwrap()
            }
        }

        /// Emscripten has no notion of a "main" stack, so just run `f`.
        pub fn on_parent_stack<F: FnOnce() -> T, T>(&self, f: F) -> T {
            f()
        }
    }

    struct Inner<I, Y, R> {
        yielder: Yielder<I, Y>,
        func: Option<Box<dyn FnOnce(&Yielder<I, Y>, I) -> R>>,
        ret: Option<R>,
        done: bool,
        _c_stack: Vec<u8>,
        _asyncify_stack: Vec<u8>,
    }

    pub struct Coroutine<I, Y, R> {
        inner: Box<Inner<I, Y, R>>,
    }

    extern "C" fn entry<I, Y, R>(arg: *mut c_void) {
        let inner = arg as *mut Inner<I, Y, R>;
        unsafe {
            let func = (*inner).func.take().unwrap();
            let input = (*(*inner).yielder.input.get()).take().unwrap();
            let ret = func(&(*inner).yielder, input);
            (*inner).ret = Some(ret);
            (*inner).done = true;
            emscripten_fiber_swap((*inner).yielder.callee.get(), (*inner).yielder.caller.get());
        }
        unreachable!();
    }

    impl<I, Y, R> Coroutine<I, Y, R> {
        pub fn new<F>(f: F) -> Self
        where
            F: FnOnce(&Yielder<I, Y>, I) -> R + 'static,
        {
            let mut inner = Box::new(Inner {
                yielder: Yielder {
                    caller: UnsafeCell::new(FiberT([0; 64])),
                    callee: UnsafeCell::new(FiberT([0; 64])),
                    caller_asyncify_stack: UnsafeCell::new(vec![0; ASYNCIFY_STACK_SIZE]),
                    input: UnsafeCell::new(None),
                    yielded: UnsafeCell::new(None),
                },
                func: Some(Box::new(f)),
                ret: None,
                done: false,
                _c_stack: vec![0; C_STACK_SIZE],
                _asyncify_stack: vec![0; ASYNCIFY_STACK_SIZE],
            });
            let arg = &mut *inner as *mut Inner<I, Y, R> as *mut c_void;
            unsafe {
                emscripten_fiber_init(
                    inner.yielder.callee.get(),
                    entry::<I, Y, R>,
                    arg,
                    inner._c_stack.as_mut_ptr().cast(),
                    C_STACK_SIZE,
                    inner._asyncify_stack.as_mut_ptr().cast(),
                    ASYNCIFY_STACK_SIZE,
                );
            }
            Coroutine { inner }
        }

        pub fn resume(&mut self, input: I) -> CoroutineResult<Y, R> {
            assert!(!self.inner.done, "Resumed a finished coroutine");
            let y = &self.inner.yielder;
            unsafe {
                *y.input.get() = Some(input);
                let stack = &mut *y.caller_asyncify_stack.get();
                emscripten_fiber_init_from_current_context(
                    y.caller.get(),
                    stack.as_mut_ptr().cast(),
                    stack.len(),
                );
                emscripten_fiber_swap(y.caller.get(), y.callee.get());
            }
            if self.inner.done {
                CoroutineResult::Return(self.inner.ret.take().unwrap())
            } else {
                CoroutineResult::Yield(unsafe { (*y.yielded.get()).take().unwrap() })
            }
        }

        pub fn done(&self) -> bool {
            self.inner.done
        }
    }

    impl<I, Y, R> Drop for Coroutine<I, Y, R> {
        fn drop(&mut self) {
            // An unfinished coroutine's stack can't be unwound; leak it rather
            // than free memory that suspended frames still point into.
            if !self.inner.done {
                let inner = std::mem::replace(
                    &mut self.inner,
                    Box::new(Inner {
                        yielder: Yielder {
                            caller: UnsafeCell::new(FiberT([0; 64])),
                            callee: UnsafeCell::new(FiberT([0; 64])),
                            caller_asyncify_stack: UnsafeCell::new(Vec::new()),
                            input: UnsafeCell::new(None),
                            yielded: UnsafeCell::new(None),
                        },
                        func: None,
                        ret: None,
                        done: true,
                        _c_stack: Vec::new(),
                        _asyncify_stack: Vec::new(),
                    }),
                );
                std::mem::forget(inner);
            }
        }
    }
}
