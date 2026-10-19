use bytecode::Bytecode;
use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    num::NonZeroU64,
};
use primitives::{OnceLock, B256, KECCAK_EMPTY, U256};

/// Byte length of an account's code, tied to the hash it was measured under.
///
/// Code outside this crate rewrites `code_hash` in place, so a bare length could go stale. Tying
/// it to the hash makes a stale record read as unknown instead of wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CodeSize {
    code_hash: B256,
    len: NonZeroU64,
}

impl CodeSize {
    /// Ties `len` to `code_hash`. `None` for the empty code hash or a zero length.
    #[inline]
    pub fn new(code_hash: B256, len: u64) -> Option<Self> {
        if code_hash == KECCAK_EMPTY {
            return None;
        }
        Some(Self {
            code_hash,
            len: NonZeroU64::new(len)?,
        })
    }

    /// The length, only if it was measured under `code_hash`.
    #[inline]
    pub fn len_for(&self, code_hash: B256) -> Option<u64> {
        (self.code_hash == code_hash).then_some(self.len.get())
    }
}

/// Account information that contains balance, nonce, code hash and code
///
/// Code is set as optional.
#[derive(Clone, Debug, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccountInfo {
    /// Account balance.
    pub balance: U256,
    /// Account nonce.
    pub nonce: u64,
    /// Hash of the raw bytes in `code`, or [`KECCAK_EMPTY`].
    pub code_hash: B256,
    /// Used as a hint to optimize the access to the storage of account.
    ///
    /// It is set when account is loaded from the database, and if it is `Some` it will called
    /// by journal to ask database the storage with this account_id (It will still send the address to the database).
    #[cfg_attr(feature = "serde", serde(skip))]
    pub account_id: Option<usize>,
    /// [`Bytecode`] data associated with this account.
    ///
    /// If [`None`], `code_hash` will be used to fetch it from the database, if code needs to be
    /// loaded from inside `revm`.
    ///
    /// By default, this is `Some(Bytecode::default())`.
    pub code: Option<Bytecode>,
    /// The length of the code at `code_hash` when recorded. Read it through
    /// [`Self::known_code_size`], which ignores a record tied to another hash. Not part of
    /// equality, hashing, ordering or serde.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub code_size: Option<CodeSize>,
}

impl Default for AccountInfo {
    fn default() -> Self {
        static DEFAULT: OnceLock<AccountInfo> = OnceLock::new();
        DEFAULT
            .get_or_init(|| Self {
                balance: U256::ZERO,
                code_hash: KECCAK_EMPTY,
                account_id: None,
                nonce: 0,
                code: Some(Bytecode::default()),
                code_size: None,
            })
            .clone()
    }
}

impl PartialEq for AccountInfo {
    fn eq(&self, other: &Self) -> bool {
        self.balance == other.balance
            && self.nonce == other.nonce
            && self.code_hash == other.code_hash
    }
}

impl Hash for AccountInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.balance.hash(state);
        self.nonce.hash(state);
        self.code_hash.hash(state);
    }
}

impl PartialOrd for AccountInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AccountInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.balance
            .cmp(&other.balance)
            .then_with(|| self.nonce.cmp(&other.nonce))
            .then_with(|| self.code_hash.cmp(&other.code_hash))
    }
}

impl AccountInfo {
    /// Creates a new [`AccountInfo`] with the given fields.
    #[inline]
    pub fn new(balance: U256, nonce: u64, code_hash: B256, code: Bytecode) -> Self {
        Self {
            balance,
            nonce,
            code: Some(code),
            code_hash,
            account_id: None,
            code_size: None,
        }
    }

    /// Returns the code length without reading bytecode, or `None` if it is unknown.
    ///
    /// The empty code hash gives `0`, present non-empty code gives its length, and otherwise a
    /// recorded [`CodeSize`] counts only if it was measured under the current `code_hash`.
    #[inline]
    pub fn known_code_size(&self) -> Option<u64> {
        if self.code_hash == KECCAK_EMPTY {
            return Some(0);
        }
        if let Some(code) = self.code.as_ref().filter(|code| !code.is_empty()) {
            return Some(code.len() as u64);
        }
        self.code_size.and_then(|size| size.len_for(self.code_hash))
    }

    /// Records `len` as the code length under the current `code_hash`; `None` clears it.
    #[inline]
    pub fn with_code_size(mut self, len: Option<u64>) -> Self {
        self.code_size = len.and_then(|len| CodeSize::new(self.code_hash, len));
        self
    }

    #[inline]
    fn retained_code_size(&self) -> Option<CodeSize> {
        self.known_code_size()
            .and_then(|len| CodeSize::new(self.code_hash, len))
    }

    /// Creates a new [`AccountInfo`] with the given code.
    ///
    /// # Note
    ///
    /// As code hash is calculated with [`Bytecode::hash_slow`] there will be performance penalty if used frequently.
    pub fn with_code(self, code: Bytecode) -> Self {
        Self {
            code_hash: code.hash_slow(),
            code: Some(code),
            ..self
        }
    }

    /// Creates a new [`AccountInfo`] with the given code hash.
    ///
    /// # Note
    ///
    /// Resets code to `None`. Not guaranteed to maintain invariant `code` and `code_hash`. See
    /// also [Self::with_code_and_hash].
    pub fn with_code_hash(self, code_hash: B256) -> Self {
        Self {
            code_hash,
            code: None,
            ..self
        }
    }

    /// Creates a new [`AccountInfo`] with the given code and code hash.
    ///
    /// # Note
    ///
    /// In debug mode panics if [`Bytecode::hash_slow`] called on `code` is not equivalent to
    /// `code_hash`. See also [`Self::with_code`].
    pub fn with_code_and_hash(self, code: Bytecode, code_hash: B256) -> Self {
        debug_assert_eq!(code.hash_slow(), code_hash);
        Self {
            code_hash,
            code: Some(code),
            ..self
        }
    }

    /// Creates a new [`AccountInfo`] with the given balance.
    pub fn with_balance(mut self, balance: U256) -> Self {
        self.balance = balance;
        self
    }

    /// Creates a new [`AccountInfo`] with the given nonce.
    pub fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    /// Sets the [`AccountInfo`] `balance`.
    #[inline]
    pub fn set_balance(&mut self, balance: U256) -> &mut Self {
        self.balance = balance;
        self
    }

    /// Sets the [`AccountInfo`] `nonce`.
    #[inline]
    pub fn set_nonce(&mut self, nonce: u64) -> &mut Self {
        self.nonce = nonce;
        self
    }

    /// Sets the [`AccountInfo`] `code_hash` and clears any cached bytecode.
    ///
    /// # Note
    ///
    /// Calling this after `set_code(...)` will remove the bytecode you just set.
    /// If you intend to mutate the code, use only `set_code`.
    #[inline]
    pub fn set_code_hash(&mut self, code_hash: B256) -> &mut Self {
        self.code = None;
        self.code_hash = code_hash;
        self
    }

    /// Replaces the [`AccountInfo`] bytecode and recalculates `code_hash`.
    ///
    /// # Note
    ///
    /// As code hash is calculated with [`Bytecode::hash_slow`] there will be performance penalty if used frequently.
    #[inline]
    pub fn set_code(&mut self, code: Bytecode) -> &mut Self {
        self.code_hash = code.hash_slow();
        self.code = Some(code);
        self
    }
    /// Sets the bytecode and its hash.
    ///
    /// # Note
    ///
    /// It is on the caller's responsibility to ensure that the bytecode hash is correct.
    pub fn set_code_and_hash(&mut self, code: Bytecode, code_hash: B256) {
        self.code_hash = code_hash;
        self.code = Some(code);
    }
    /// Returns a copy of this account with the [`Bytecode`] removed.
    ///
    /// This is useful when creating journals or snapshots of the state, where it is
    /// desirable to store the code blobs elsewhere.
    ///
    /// ## Note
    ///
    /// This is distinct from [`without_code`][Self::without_code] in that it returns
    /// a new [`AccountInfo`] instance with the code removed.
    ///
    /// [`without_code`][Self::without_code] will modify and return the same instance.
    #[inline]
    pub fn copy_without_code(&self) -> Self {
        Self {
            balance: self.balance,
            nonce: self.nonce,
            code_hash: self.code_hash,
            account_id: self.account_id,
            code: None,
            code_size: self.retained_code_size(),
        }
    }

    /// Strips the [`Bytecode`] from this account and drop it.
    ///
    /// This is useful when creating journals or snapshots of the state, where it is
    /// desirable to store the code blobs elsewhere.
    ///
    /// ## Note
    ///
    /// This is distinct from [`copy_without_code`][Self::copy_without_code] in that it
    /// modifies the account in place.
    ///
    /// [`copy_without_code`][Self::copy_without_code]
    /// will copy the non-code fields and return a new [`AccountInfo`] instance.
    pub fn without_code(mut self) -> Self {
        self.take_bytecode();
        self
    }

    /// Returns if an account is empty.
    ///
    /// An account is empty if the following conditions are met.
    /// - code hash is zero or set to the Keccak256 hash of the empty string `""`
    /// - balance is zero
    /// - nonce is zero
    #[inline]
    pub fn is_empty(&self) -> bool {
        let code_empty = self.is_empty_code_hash() || self.code_hash.is_zero();
        code_empty && self.balance.is_zero() && self.nonce == 0
    }

    /// Returns `true` if the account is not empty.
    #[inline]
    pub fn exists(&self) -> bool {
        !self.is_empty()
    }

    /// Returns `true` if account has no nonce and code.
    #[inline]
    pub fn has_no_code_and_nonce(&self) -> bool {
        self.is_empty_code_hash() && self.nonce == 0
    }

    /// Returns bytecode hash associated with this account.
    ///
    /// If account does not have code, it returns `KECCAK_EMPTY` hash.
    #[inline]
    pub fn code_hash(&self) -> B256 {
        self.code_hash
    }

    /// Returns true if the code hash is the Keccak256 hash of the empty string `""`.
    #[inline]
    pub fn is_empty_code_hash(&self) -> bool {
        self.code_hash == KECCAK_EMPTY
    }

    /// Takes bytecode from account.
    ///
    /// Code will be set to [None].
    #[inline]
    pub fn take_bytecode(&mut self) -> Option<Bytecode> {
        self.code_size = self.retained_code_size();
        self.code.take()
    }

    /// Initializes an [`AccountInfo`] with the given balance, setting all other fields to their
    /// default values.
    #[inline]
    pub fn from_balance(balance: U256) -> Self {
        AccountInfo {
            balance,
            ..Default::default()
        }
    }

    /// Initializes an [`AccountInfo`] with the given bytecode, setting its balance to zero, its
    /// nonce to `1`, and calculating the code hash from the given bytecode.
    #[inline]
    pub fn from_bytecode(bytecode: Bytecode) -> Self {
        let hash = bytecode.hash_slow();

        AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code: Some(bytecode),
            code_hash: hash,
            account_id: None,
            code_size: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{AccountInfo, CodeSize};
    use bytecode::Bytecode;
    use core::{
        cmp::Ordering,
        hash::{Hash, Hasher},
    };
    use primitives::{Bytes, B256, KECCAK_EMPTY};
    use std::collections::{hash_map::DefaultHasher, BTreeSet};

    fn contract() -> AccountInfo {
        AccountInfo::from_bytecode(Bytecode::new_raw(Bytes::from_static(&[
            0x60, 0x00, 0x60, 0x00,
        ])))
    }

    #[test]
    fn known_code_size_rules() {
        let hash = B256::repeat_byte(0x11);

        assert_eq!(AccountInfo::default().known_code_size(), Some(0));
        assert_eq!(
            AccountInfo::default()
                .with_code_size(Some(7))
                .known_code_size(),
            Some(0),
            "empty code hash wins over any record"
        );
        assert_eq!(contract().known_code_size(), Some(4));

        let mut recorded = AccountInfo::default()
            .with_code_hash(hash)
            .with_code_size(Some(7));
        assert_eq!(recorded.known_code_size(), Some(7));
        recorded.code_hash = B256::repeat_byte(0x22);
        assert_eq!(recorded.known_code_size(), None, "stale tag reads unknown");

        let unrecorded = AccountInfo::default().with_code_hash(hash);
        assert_eq!(unrecorded.known_code_size(), None);
        assert_eq!(
            unrecorded.clone().with_code_size(Some(0)).known_code_size(),
            None
        );
        assert_eq!(
            AccountInfo::default()
                .with_code_hash(hash)
                .with_code_size(Some(7))
                .with_code_size(None)
                .known_code_size(),
            None
        );

        assert_eq!(CodeSize::new(KECCAK_EMPTY, 7), None);
        assert_eq!(CodeSize::new(hash, 0), None);
        assert_eq!(CodeSize::new(hash, 7).unwrap().len_for(hash), Some(7));
        assert_eq!(
            CodeSize::new(hash, 7)
                .unwrap()
                .len_for(B256::repeat_byte(0x22)),
            None
        );
    }

    #[test]
    fn dropping_code_keeps_code_size() {
        let copy = contract().copy_without_code();
        assert!(copy.code.is_none());
        assert_eq!(copy.known_code_size(), Some(4));

        let stripped = contract().without_code();
        assert!(stripped.code.is_none());
        assert_eq!(stripped.known_code_size(), Some(4));

        let mut taken = contract();
        assert!(taken.take_bytecode().is_some());
        assert_eq!(taken.known_code_size(), Some(4));

        taken.code_hash = B256::repeat_byte(0x22);
        assert_eq!(taken.known_code_size(), None);
    }

    #[test]
    fn code_size_is_not_identity() {
        let hash = B256::repeat_byte(0x11);
        let with_size = AccountInfo::default()
            .with_code_hash(hash)
            .with_code_size(Some(7));
        let without_size = AccountInfo::default().with_code_hash(hash);

        assert_eq!(with_size, without_size);
        assert_eq!(with_size.cmp(&without_size), Ordering::Equal);

        let digest = |info: &AccountInfo| {
            let mut hasher = DefaultHasher::new();
            info.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(digest(&with_size), digest(&without_size));
    }

    #[test]
    fn test_account_info_trait_consistency() {
        let bytecode = Bytecode::default();
        let account1 = AccountInfo {
            code: Some(bytecode),
            ..AccountInfo::default()
        };

        let account2 = AccountInfo::default();

        assert_eq!(account1, account2, "Accounts should be equal ignoring code");

        assert_eq!(
            account1.cmp(&account2),
            Ordering::Equal,
            "Ordering should be equal after ignoring code in Ord"
        );

        #[allow(clippy::mutable_key_type)] // Not observable
        let mut set = BTreeSet::new();
        assert!(set.insert(account1.clone()), "Inserted account1");
        assert!(
            !set.insert(account2.clone()),
            "account2 not inserted (treated as duplicate)"
        );

        assert_eq!(set.len(), 1, "Set should have only one unique account");
        assert!(set.contains(&account1), "Set contains account1");
        assert!(
            set.contains(&account2),
            "Set contains account2 (since equal)"
        );

        let mut accounts = [account2, account1];
        accounts.sort();
        assert_eq!(accounts[0], accounts[1], "Sorted vec treats them as equal");
    }
}
