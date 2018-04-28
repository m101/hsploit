all:
	cargo build --target i686-pc-windows-gnu

clean:
	cargo clean
	rm Cargo.lock

