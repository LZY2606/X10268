//! 稳定身份：所有可显示对象的 id 由其稳定语义键经 FNV-1a 64 派生。
//! 不使用 SQLite rowid，因此导出、删除本地数据库、再导入后身份与顺序保持不变。

pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// 由层级化键生成短稳定 id，例如 `id!("evt", case_id, n)`。
#[macro_export]
macro_rules! sid {
    ($($part:expr),+ $(,)?) => {{
        let mut k = String::new();
        $(
            k.push_str(&format!("{}|", $part));
        )+
        let h = $crate::ids::fnv1a64(k.trim_end_matches('|').as_bytes());
        format!("{:016x}", h)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_across_calls() {
        assert_eq!(sid!("evt", "c1", 3), sid!("evt", "c1", 3));
        assert_ne!(sid!("evt", "c1", 3), sid!("evt", "c1", 4));
    }

    #[test]
    fn known_vector() {
        assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);
    }
}
