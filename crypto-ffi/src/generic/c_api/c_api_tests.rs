use super::*;

fn init() -> CoreCryptoPtrMut {
    unsafe {
        let path = CStr::from_bytes_with_nul_unchecked(b"test.edb\0");
        let key = CStr::from_bytes_with_nul_unchecked(b"test\0");
        let client_id = CStr::from_bytes_with_nul_unchecked(b"test12345\0");
        cc_init_with_path_and_key(path.as_ptr(), key.as_ptr(), client_id.as_ptr(), std::ptr::null())
    }
}

fn teardown(cc: CoreCryptoPtrMut) {
    unsafe { cc_wipe(cc) };
}

fn run_test<T>(test: T)
where
    T: FnOnce(CoreCryptoPtrMut) -> () + std::panic::UnwindSafe,
{
    let cc = init();
    let result = std::panic::catch_unwind(move || test(cc));
    teardown(cc);
    assert!(result.is_ok());
}

fn check_error<const T: usize>(res: &CallStatus<T>) {
    if res.status == -1 {
        let len = cc_last_error_len();
        let mut buf = vec![0u8; len];
        cc_last_error(buf.as_mut_ptr() as _);
        let cstr = CString::from_vec_with_nul(buf).unwrap();
        panic!("{}", cstr.to_str().unwrap());
    }
}

#[test]
fn can_init_cc() {
    run_test(|cc| {
        assert!(!cc.is_null());
    })
}

#[test]
fn can_read_version() {
    let version_str = unsafe { CStr::from_ptr(cc_version() as _) };
    assert_eq!(version_str.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn can_get_client_pk() {
    run_test(|cc| {
        let mut buf = [0u8; 48];
        let res = unsafe { cc_client_public_key(cc, buf.as_mut_ptr()) };
        check_error(&res);

        assert_ne!(buf, [0u8; 48]);
        let kp_len = res.written[0];
        let kp = &buf[..kp_len];
        assert_ne!(kp, vec![0u8; kp_len]);
    })
}

#[test]
fn can_get_client_keypackages() {
    run_test(|cc| {
        let amount_requested = 200;
        let base_slice = [0u8; 2048];
        let mut buf = vec![base_slice; amount_requested];
        let mut ptr_buf: Vec<*mut u8> = buf.iter_mut().map(|s| s.as_mut_ptr()).collect();
        let res = unsafe { cc_client_keypackages(cc, amount_requested, ptr_buf.as_mut_ptr(), base_slice.len()) };
        check_error(&res);
        for kp in buf {
            assert_ne!(kp, base_slice);
        }
    })
}
