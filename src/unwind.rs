use std::{any::Any, error::Error};

/// Tries to get meaningful description from panic-error.
pub(crate) fn any_to_string(any: Box<dyn Any + Send>) -> String {
    if let Some(s) = any.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = any.downcast_ref::<String>() {
        s.clone()
    } else if let Some(error) = any.downcast_ref::<Box<dyn Error + Send>>() {
        error.to_string()
    } else {
        "Unknown error occurred".to_string()
    }
}

macro_rules! ffi_export {

    // For functions returning an opaque pointer (*mut T doesn't implement Default)
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $($arg:ident : $arg_ty:ty),* $(,)*
        ) -> *mut $ret_ty:ty $body:block
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "C" fn $fn_name($($arg : $arg_ty),*) -> *mut $ret_ty {
            match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(move || $body)) {
                Ok(x) => return x,
                Err(e) => {
                    eprintln!("Panic occured: {:?}", &any_to_string(e));
                    return null_mut()
                }
            }
        }
    );

    // For functions returning a type implementing Default
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $($arg:ident : $arg_ty:ty),* $(,)*
        ) -> $ret_ty:ty $body:block
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "C" fn $fn_name($($arg : $arg_ty),*) -> $ret_ty {
            match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(move || $body)) {
                Ok(x) => return x,
                Err(e) => {
                    eprintln!("Panic occured: {:?}", &any_to_string(e));
                    return <$ret_ty as Default>::default()
                }
            }
        }
    );

    // For functions returning void
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $($arg:ident : $arg_ty:ty),* $(,)*
        ) $body:block
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "C" fn $fn_name($($arg : $arg_ty),*) {
            match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(move || $body)) {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("Panic occured: {:?}", &any_to_string(e));
                }
            }
        }
    );
}

macro_rules! ffi_export_with_ret_code {

    // For functions returning an opaque pointer (*mut T doesn't implement Default)
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $ret_code:ident : $ret_code_ty: ty, $($arg:ident : $arg_ty:ty),* $(,)*
        ) -> *mut $ret_ty:ty $body:block
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "C" fn $fn_name($($arg : $arg_ty),*, $ret_code : $ret_code_ty) -> *mut $ret_ty {
            match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| $body)) {
                Ok(x) => return x,
                Err(e) => {
                    *$ret_code = CctpErrorCode::PanicOccured;
                    eprintln!("Panic occured: {:?}", &any_to_string(e));
                    return null_mut()
                }
            }
        }
    );

    // For functions returning a type implementing Default
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $ret_code:ident : $ret_code_ty: ty, $($arg:ident : $arg_ty:ty),* $(,)*
        ) -> $ret_ty:ty $body:block
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "C" fn $fn_name($($arg : $arg_ty),*, $ret_code : $ret_code_ty) -> $ret_ty {
            match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| $body)) {
                Ok(x) => return x,
                Err(e) => {
                    *$ret_code = CctpErrorCode::PanicOccured;
                    eprintln!("Panic occured: {:?}", &any_to_string(e));
                    return <$ret_ty as Default>::default()
                }
            }
        }
    );

    // For functions returning void
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $ret_code:ident : $ret_code_ty: ty, $($arg:ident : $arg_ty:ty),* $(,)*
        ) $body:block
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "C" fn $fn_name($($arg : $arg_ty),* $ret_code : $ret_code_ty) {
            match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| $body)) {
                Ok(_) => {},
                Err(e) => {
                    *$ret_code = CctpErrorCode::PanicOccured;
                    eprintln!("Panic occured: {:?}", &any_to_string(e));
                }
            }
        }
    );
}