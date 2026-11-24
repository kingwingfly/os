(module
  (import "os" "sys" (func $sys (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "[{\"open_at\":{\"dirfd\":3,\"path\":\"/dev/input\",\"flags\":0}},{\"open\":{\"path\":\"/dev/display\",\"flags\":1}},{\"open_at\":{\"dirfd\":3,\"path\":\"/dev/input\",\"flags\":2097152}}]")
  (func $check (param $fd i32) (param $type i32) (param $expected i32)
    ;; Each call also subscribes to a zero-duration clock at offset 48.
    (i32.store8 (i32.const 8) (local.get $type))
    (i32.store (i32.const 16) (local.get $fd))
    (if (call $poll (i32.const 0) (i32.const 128) (i32.const 2) (i32.const 256)) (then unreachable))
    (if (i32.lt_s (local.get $expected) (i32.const 0))
      (then (if (i32.ne (i32.load (i32.const 256)) (i32.const 1)) (then unreachable)))
      (else
        (if (i32.ne (i32.load (i32.const 256)) (i32.const 2)) (then unreachable))
        (if (i32.ne (i32.load16_u (i32.const 136)) (local.get $expected)) (then unreachable)))))
  (func (export "_start") (local $len i32)
    (loop $length
      (if (i32.load8_u (i32.add (i32.const 1024) (local.get $len)))
        (then (local.set $len (i32.add (local.get $len) (i32.const 1))) (br $length))))
    (drop (call $sys (i32.const 1024) (local.get $len)))
    ;; Standard I/O and the root preopen occupy 0..3 in this fresh guest.
    (call $check (i32.const 4) (i32.const 1) (i32.const -1)) ;; empty input
    (call $check (i32.const 4) (i32.const 2) (i32.const 8))  ;; write on input
    (call $check (i32.const 5) (i32.const 1) (i32.const 8))  ;; read on display
    (call $check (i32.const 5) (i32.const 2) (i32.const 0))  ;; writable display
    (call $check (i32.const 6) (i32.const 1) (i32.const 8)))) ;; O_PATH input
