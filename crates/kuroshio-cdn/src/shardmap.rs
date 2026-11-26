//! 依名稱雜湊分片的網域表（3.5.1）：記憶體裡也照磁碟分片（[`crate::db::shard_of`]，FNV-1a 的低位元）分成 N 個雜湊表。
//!
//! 為什麼：以前整個網域資料庫是一個雜湊表，寫一個分片要先掃過全部網域找出屬於這片的（7 萬筆在 x86 上 4 ms、
//! MT7621 上約 60 ms，而且拿著狀態鎖）；寫全部 256 片就是 256 次全表掃描，D3 上佔滿一個核心約 20 秒，
//! 查詢（快取命中的也要拿這把鎖）一直等不到鎖。分開放之後一片只看自己的表，大批處理（冷資料移出、淘汰、
//! 一次性網域清理）也能一次做幾片、中間放開鎖，結果跟一次做完一樣。
//!
//! 查詢路徑多一次 FNV-1a（名稱的每個位元組一次 xor、一次乘法），換到的是每個表小很多。

use std::collections::HashMap;
use std::sync::Arc;

pub struct ShardMap<V> {
    maps: Vec<HashMap<Arc<str>, V>>,
    len: usize,
}

impl<V> ShardMap<V> {
    /// `n` 個分片（2 的次方，至少 1）
    pub fn new(n: usize) -> Self {
        let n = n.max(1).next_power_of_two();
        ShardMap {
            maps: (0..n).map(|_| HashMap::new()).collect(),
            len: 0,
        }
    }

    /// 分片數
    pub fn shards(&self) -> usize {
        self.maps.len()
    }

    /// 改分片數：全部重新分配（測試、量測用；正式執行時分片數只在建立時決定）
    pub fn set_shards(&mut self, n: usize) {
        let n = n.max(1).next_power_of_two();
        if n == self.maps.len() {
            return;
        }
        let old = std::mem::replace(&mut self.maps, (0..n).map(|_| HashMap::new()).collect());
        self.len = 0;
        for m in old {
            for (k, v) in m {
                self.insert(k, v);
            }
        }
    }

    #[inline]
    fn idx(&self, name: &str) -> usize {
        crate::db::shard_of(name, self.maps.len())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 所有表配置的格數合計
    pub fn capacity(&self) -> usize {
        self.maps.iter().map(HashMap::capacity).sum()
    }

    pub fn get(&self, name: &str) -> Option<&V> {
        self.maps[self.idx(name)].get(name)
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut V> {
        let i = self.idx(name);
        self.maps[i].get_mut(name)
    }

    pub fn contains_key(&self, name: &str) -> bool {
        self.maps[self.idx(name)].contains_key(name)
    }

    pub fn insert(&mut self, name: Arc<str>, v: V) -> Option<V> {
        let i = self.idx(&name);
        let old = self.maps[i].insert(name, v);
        if old.is_none() {
            self.len += 1;
        }
        old
    }

    /// 沒有就用 `f()` 新增，回傳那一筆
    pub fn get_or_insert_with(&mut self, name: Arc<str>, f: impl FnOnce() -> V) -> &mut V {
        let i = self.idx(&name);
        let m = &mut self.maps[i];
        if !m.contains_key(&name) {
            self.len += 1;
        }
        m.entry(name).or_insert_with(f)
    }

    pub fn remove(&mut self, name: &str) -> Option<V> {
        let i = self.idx(name);
        let v = self.maps[i].remove(name);
        if v.is_some() {
            self.len -= 1;
        }
        v
    }

    pub fn clear(&mut self) {
        self.maps.iter_mut().for_each(HashMap::clear);
        self.len = 0;
    }

    /// 預留大約 `add` 筆（平均分到各片）
    pub fn reserve(&mut self, add: usize) {
        let each = add.div_ceil(self.maps.len());
        self.maps.iter_mut().for_each(|m| m.reserve(each));
    }

    pub fn shrink_to_fit(&mut self) {
        self.maps.iter_mut().for_each(HashMap::shrink_to_fit);
    }

    /// 只把第 `i` 片的表縮回去
    pub fn shrink_shard(&mut self, i: usize) {
        if let Some(m) = self.maps.get_mut(i) {
            m.shrink_to_fit();
        }
    }

    pub fn retain(&mut self, mut f: impl FnMut(&Arc<str>, &mut V) -> bool) {
        let mut len = 0;
        for m in &mut self.maps {
            m.retain(&mut f);
            len += m.len();
        }
        self.len = len;
    }

    /// 清空第 `i` 片
    pub fn clear_shard(&mut self, i: usize) {
        if let Some(m) = self.maps.get_mut(i) {
            self.len -= m.len();
            m.clear();
        }
    }

    /// 第 `i` 片（唯讀）
    pub fn shard(&self, i: usize) -> &HashMap<Arc<str>, V> {
        &self.maps[i]
    }

    /// 第 `i` 片的內容（可以改，不能增刪）
    pub fn shard_values_mut(&mut self, i: usize) -> impl Iterator<Item = &mut V> {
        self.maps[i].values_mut()
    }

    pub fn keys(&self) -> impl Iterator<Item = &Arc<str>> {
        self.maps.iter().flat_map(HashMap::keys)
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.maps.iter().flat_map(HashMap::values)
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.maps.iter_mut().flat_map(HashMap::values_mut)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Arc<str>, &V)> {
        self.maps.iter().flat_map(HashMap::iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ops_keep_len_and_shard() {
        let mut m: ShardMap<u32> = ShardMap::new(8);
        for i in 0..200u32 {
            assert!(m.insert(Arc::from(format!("n{i}.example.com").as_str()), i).is_none());
        }
        assert_eq!(m.len(), 200);
        assert!(m.insert(Arc::from("n1.example.com"), 9).is_some(), "同名蓋過去、筆數不變");
        assert_eq!(m.len(), 200);
        for i in 0..8 {
            assert!(m.shard(i).keys().all(|k| crate::db::shard_of(k, 8) == i), "每片只有自己的");
        }
        assert_eq!(m.remove("n2.example.com"), Some(2));
        assert_eq!(m.remove("n2.example.com"), None);
        assert_eq!(m.len(), 199);
        *m.get_or_insert_with(Arc::from("new.example.com"), || 7) += 1;
        assert_eq!(m.get("new.example.com"), Some(&8));
        *m.get_or_insert_with(Arc::from("new.example.com"), || 100) += 1;
        assert_eq!(m.get("new.example.com"), Some(&9));
        assert_eq!(m.len(), 200);
        m.retain(|_, v| *v % 2 == 0);
        assert_eq!(m.len(), m.values().count());
        let i = m.idx("n4.example.com");
        let before = m.len();
        let in_shard = m.shard(i).len();
        m.clear_shard(i);
        assert_eq!(m.len(), before - in_shard);
        m.set_shards(2);
        assert_eq!(m.shards(), 2);
        assert_eq!(m.len(), before - in_shard);
        assert_eq!(m.keys().count(), m.len());
        m.clear();
        assert!(m.is_empty());
    }
}
