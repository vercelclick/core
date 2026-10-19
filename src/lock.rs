pub trait HashedLock {
    fn salt(&self) -> Vec<String>;
}
