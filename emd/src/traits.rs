pub trait HumanReadable {
	fn bytes_as_hrb(self) -> String;
}

impl HumanReadable for u64 {
	fn bytes_as_hrb(self) -> String {
		const DIVISOR: f64 = 1024.0; //Yes, it's 1024 - because we will calculate MiB, not MB (like storage manufacturers). ;)
		const UNIT: [&str; 9] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"];
		let mut current_multiplier = 1.0;
		let mut humanreadable_size = String::new();
		let size = self as f64;
		while (size) >= DIVISOR.powf(current_multiplier) {
			current_multiplier += 1.0;
		}
		humanreadable_size.push_str(&(format!("{:.2}", (size) / DIVISOR.powf(current_multiplier - 1.0))));
		humanreadable_size.push_str(UNIT[(current_multiplier - 1.0) as usize]);
		humanreadable_size
	}
}