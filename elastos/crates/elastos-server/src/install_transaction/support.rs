//! Hash-bound support trees share the release journal and its recovery owner.
use super::*;

pub(super) const SCRATCH: &str = ".elastos.update-support";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub path: PathBuf,
    original: Option<String>,
    candidate: Option<String>,
}

fn scratch(tx: &InstallTransaction, index: usize, candidate: bool) -> PathBuf {
    tx.data_dir.join(SCRATCH).join(format!(
        "{}-{index}",
        if candidate { "stage" } else { "rollback" }
    ))
}

// Delivery copies are consumed by atomic renames. stage/rollback remain the
// immutable, journal-bound recovery sources until the transaction is retired.
fn delivery(tx: &InstallTransaction, index: usize, candidate: bool) -> PathBuf {
    tx.data_dir.join(SCRATCH).join(format!(
        "{}-{index}",
        if candidate { "activate" } else { "restore" }
    ))
}

/// The signed model catalogue is the one top-level file a release's support may replace.
const MODEL_CATALOG: &str = "model-catalog.json";

pub(crate) fn validate_support_path(path: &Path) -> anyhow::Result<()> {
    if path == Path::new(MODEL_CATALOG) {
        return Ok(());
    }
    let mut parts = path.components();
    anyhow::ensure!(matches!(parts.next(), Some(std::path::Component::Normal(name)) if ["bin", "capsules", "libexec", "tools", "scripts"].iter().any(|allowed| name == *allowed))
        && parts.all(|part| matches!(part, std::path::Component::Normal(name) if !name.to_string_lossy().starts_with(".elastos."))), "unsafe release support path");
    Ok(())
}

pub(super) fn validate_entries(tx: &InstallTransaction, entries: &[Entry]) -> anyhow::Result<()> {
    for (index, entry) in entries.iter().enumerate() {
        let path = &entry.path;
        validate_support_path(path)?;
        if path.components().count() == 1
            && path != Path::new(MODEL_CATALOG)
            && (entry.original.is_some() || entry.candidate.is_none())
            || tx
                .destinations
                .values()
                .any(|dest| dest.starts_with(tx.data_dir.join(path)))
            || entries[..index]
                .iter()
                .any(|other| other.path.starts_with(path) || path.starts_with(&other.path))
            || entry
                .original
                .as_ref()
                .is_some_and(|hash| !valid_hash(hash))
            || entry
                .candidate
                .as_ref()
                .is_some_and(|hash| !valid_hash(hash))
        {
            bail!("unsafe or overlapping release support path");
        }
        tx.check_parent(tx.data_dir.join(path).parent().unwrap(), false)?;
    }
    Ok(())
}

// The digest frames names, types, modes, lengths and link targets, independent of
// the tree's stage/live/rollback location. Open regular files without following links.
fn state(path: &Path) -> anyhow::Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    fn visit(path: &Path, hash: &mut Sha256) -> anyhow::Result<()> {
        let meta = fs::symlink_metadata(path)?;
        if meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o7022 != 0 && !meta.file_type().is_symlink()
        {
            bail!("unsafe release support ownership or mode at {}. Keep recovery files for operator repair.", path.display());
        }
        hash.update((meta.mode() & 0o777).to_le_bytes());
        if meta.file_type().is_symlink() {
            hash.update(b"link");
            let target = fs::read_link(path)?;
            let bytes = target.as_os_str().as_encoded_bytes();
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        } else if meta.is_dir() {
            hash.update(b"directory");
            let mut children = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
            children.sort_by_key(|child| child.file_name());
            hash.update((children.len() as u64).to_le_bytes());
            for child in children {
                let name = child.file_name();
                let bytes = name.as_encoded_bytes();
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(bytes);
                visit(&child.path(), hash)?;
            }
        } else if meta.is_file() {
            hash.update(b"file");
            hash.update(meta.len().to_le_bytes());
            let mut input = open_read(path)?;
            check_file(&input, path, false)?;
            std::io::copy(&mut input, &mut HashWriter(hash))?;
        } else {
            bail!("unsupported release support file type");
        }
        Ok(())
    }
    let mut digest = Sha256::new();
    visit(path, &mut digest)?;
    Ok(Some(hex::encode(digest.finalize())))
}

struct HashWriter<'a>(&'a mut Sha256);
impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn copy_tree(source: &Path, dest: &Path) -> anyhow::Result<()> {
    let meta = fs::symlink_metadata(source)?;
    if meta.file_type().is_symlink() {
        std::os::unix::fs::symlink(fs::read_link(source)?, dest)?;
        let name = std::ffi::CString::new(dest.as_os_str().as_encoded_bytes())?;
        let times = [
            libc::timespec {
                tv_sec: meta.atime(),
                tv_nsec: meta.atime_nsec() as _,
            },
            libc::timespec {
                tv_sec: meta.mtime(),
                tv_nsec: meta.mtime_nsec() as _,
            },
        ];
        if unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                name.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
    } else if meta.is_dir() {
        fs::DirBuilder::new()
            .mode(meta.mode() & 0o777)
            .create(dest)?;
        for child in fs::read_dir(source)? {
            let child = child?;
            copy_tree(&child.path(), &dest.join(child.file_name()))?;
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dest)?;
        directory.set_permissions(fs::Permissions::from_mode(meta.mode() & 0o777))?;
        directory.set_times(fs::FileTimes::new().set_modified(meta.modified()?))?;
        sync_directory(dest)?;
    } else if meta.is_file() {
        let mut input = open_read(source)?;
        let mut output = open_new(dest, meta.mode() & 0o777)?;
        let mut buffer = [0; 64 * 1024];
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            let (total, available) = disk_space(dest.parent().unwrap())?;
            require_update_space(total, available, count as u128)?;
            output.write_all(&buffer[..count])?;
        }
        output.set_permissions(fs::Permissions::from_mode(meta.mode() & 0o777))?;
        output.set_times(fs::FileTimes::new().set_modified(meta.modified()?))?;
        output.sync_all()?;
    } else {
        bail!("unsupported release support file type");
    }
    Ok(())
}

fn remove(path: &Path) -> anyhow::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(super) fn prepare(tx: &InstallTransaction, paths: &[(PathBuf, PathBuf)]) -> anyhow::Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut journal = tx.read_journal()?.context("prepared release missing")?;
    anyhow::ensure!(
        journal.phase == Phase::Prepared && journal.support.is_empty() && journal.restart.is_none(),
        "support staging requires a prepared release"
    );
    for (relative, source) in paths {
        validate_support_path(relative)?;
        anyhow::ensure!(
            relative.components().count() > 1
                || relative == Path::new(MODEL_CATALOG)
                || source.is_dir(),
            "new support root must be a directory"
        );
        journal.support.push(Entry {
            path: relative.clone(),
            original: state(&tx.data_dir.join(relative))?,
            candidate: if source.as_os_str().is_empty() {
                None
            } else {
                state(source)?
            },
        });
    }
    validate_entries(tx, &journal.support)?;
    let directory = tx.data_dir.join(SCRATCH);
    anyhow::ensure!(
        !directory.exists(),
        "unresolved support scratch requires recovery"
    );
    // Journal before any scratch allocation. Staging leaves the live set intact.
    journal.phase = Phase::Staging;
    tx.write_journal(&journal)?;
    let result = (|| {
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        sync_directory(&tx.data_dir)?;
        for (index, entry) in journal.support.iter().enumerate() {
            if entry.candidate.is_some() {
                copy_tree(&paths[index].1, &scratch(tx, index, true))?;
                copy_tree(&scratch(tx, index, true), &delivery(tx, index, true))?;
            }
            if entry.original.is_some() {
                copy_tree(&tx.data_dir.join(&entry.path), &scratch(tx, index, false))?;
                copy_tree(&scratch(tx, index, false), &delivery(tx, index, false))?;
            }
            require_original(tx, &journal.support)?;
        }
        journal.phase = Phase::Prepared;
        tx.write_journal(&journal)?;
        validate_scratch(tx, &journal)
    })();
    tx.restore_on_error(result)
}

pub(super) fn require_original(tx: &InstallTransaction, entries: &[Entry]) -> anyhow::Result<()> {
    require_installed(tx, entries, true)
}

pub(super) fn require_installed(
    tx: &InstallTransaction,
    entries: &[Entry],
    previous: bool,
) -> anyhow::Result<()> {
    for entry in entries {
        anyhow::ensure!(
            state(&tx.data_dir.join(&entry.path))?
                == if previous {
                    entry.original.clone()
                } else {
                    entry.candidate.clone()
                },
            "installed release support changed at {}. Keep recovery files and run `elastos home --browser` to finish recovery.",
            tx.data_dir.join(&entry.path).display()
        );
    }
    Ok(())
}

pub(super) fn validate_scratch(tx: &InstallTransaction, journal: &Journal) -> anyhow::Result<()> {
    let directory = tx.data_dir.join(SCRATCH);
    if !directory.exists() {
        if !journal.support.is_empty() && journal.phase != Phase::Staging {
            let previous = match journal.restart.as_ref().map(|restart| restart.phase) {
                Some(RestartPhase::CandidateReady) => false,
                Some(RestartPhase::PreviousReady) => true,
                _ => bail!("support scratch missing; retain recovery journal"),
            };
            require_installed(tx, &journal.support, previous)?;
        }
        return Ok(());
    }
    check_private_directory(&directory)?;
    for item in fs::read_dir(&directory)? {
        let item = item?;
        let mut found = false;
        for (index, entry) in journal.support.iter().enumerate() {
            for candidate in [false, true] {
                if item.path() == scratch(tx, index, candidate)
                    || item.path() == delivery(tx, index, candidate)
                {
                    // An interrupted copy has no activation authority.
                    if journal.phase != Phase::Staging {
                        anyhow::ensure!(
                            state(&item.path())?
                                == if candidate {
                                    entry.candidate.clone()
                                } else {
                                    entry.original.clone()
                                },
                            "release support scratch changed at {}. Keep recovery files for operator repair.", item.path().display()
                        );
                    }
                    found = true;
                }
            }
        }
        anyhow::ensure!(found, "foreign release support scratch");
    }
    if matches!(journal.phase, Phase::Prepared) {
        for (index, entry) in journal.support.iter().enumerate() {
            anyhow::ensure!(
                state(&scratch(tx, index, true))? == entry.candidate
                    && state(&scratch(tx, index, false))? == entry.original,
                "incomplete release support stage"
            );
        }
    }
    Ok(())
}

pub(super) fn activate(tx: &InstallTransaction, entries: &[Entry]) -> anyhow::Result<()> {
    require_original(tx, entries)?;
    for (index, entry) in entries.iter().enumerate() {
        if entry.original.is_none() && entry.candidate.is_none() {
            continue;
        }
        let destination = tx.data_dir.join(&entry.path);
        tx.check_parent(destination.parent().unwrap(), true)?;
        remove(&destination)?;
        sync_directory(destination.parent().unwrap())?;
        if entry.candidate.is_some() {
            let prepared = delivery(tx, index, true);
            // Journals from older controllers have only the stage copy.
            fs::rename(
                if fs::symlink_metadata(&prepared).is_ok() {
                    prepared
                } else {
                    scratch(tx, index, true)
                },
                &destination,
            )?;
        }
        sync_directory(destination.parent().unwrap())?;
    }
    require_installed(tx, entries, false)
}

// This is a repair plan, never a replacement digest. Every source file, mode,
// and link must still match a journal-bound copy. Only regular Python cache
// files with a recorded source can be replaced or removed before exact hashing.
fn cache_drift_only(current: &Path, recorded: &Path) -> anyhow::Result<bool> {
    if state(current)? == state(recorded)? {
        return Ok(true);
    }
    let live = fs::symlink_metadata(current).ok();
    let saved = fs::symlink_metadata(recorded).ok();
    if live.as_ref().is_some_and(|m| m.file_type().is_symlink())
        || saved.as_ref().is_some_and(|m| m.file_type().is_symlink())
    {
        return Ok(false);
    }
    let cache_directory = current
        .file_name()
        .is_some_and(|name| name == "__pycache__");
    if cache_directory {
        for directory in [current, recorded] {
            if let Ok(meta) = fs::symlink_metadata(directory) {
                if !meta.is_dir() {
                    return Ok(false);
                }
                for child in fs::read_dir(directory)? {
                    let child = child?;
                    let name = child.file_name();
                    let name = name.to_string_lossy();
                    let meta = fs::symlink_metadata(child.path())?;
                    let source = recorded
                        .parent()
                        .unwrap()
                        .join(format!("{}.py", name.split('.').next().unwrap_or("")));
                    if !meta.is_file()
                        || !name.ends_with(".pyc")
                        || !fs::symlink_metadata(source).is_ok_and(|m| m.is_file())
                    {
                        return Ok(false);
                    }
                }
            }
        }
        return Ok(true);
    }
    match (live, saved) {
        (Some(live), Some(saved))
            if live.is_dir() && saved.is_dir() && live.mode() == saved.mode() =>
        {
            let mut names = BTreeSet::new();
            for directory in [current, recorded] {
                for child in fs::read_dir(directory)? {
                    names.insert(child?.file_name());
                }
            }
            for name in names {
                if !cache_drift_only(&current.join(&name), &recorded.join(&name))? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn has_recorded_cache_repair(
    tx: &InstallTransaction,
    index: usize,
    entry: &Entry,
) -> anyhow::Result<bool> {
    for (candidate, expected) in [(true, &entry.candidate), (false, &entry.original)] {
        let recorded = scratch(tx, index, candidate);
        if expected.is_some()
            && state(&recorded)? == *expected
            && cache_drift_only(&tx.data_dir.join(&entry.path), &recorded)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn validate_restore(tx: &InstallTransaction, entries: &[Entry]) -> anyhow::Result<()> {
    let allow_missing = tx
        .read_journal()?
        .is_some_and(|journal| matches!(journal.phase, Phase::Committing | Phase::Recovering));
    for (index, entry) in entries.iter().enumerate() {
        let current = state(&tx.data_dir.join(&entry.path))?;
        anyhow::ensure!(
            current == entry.original
                || current == entry.candidate
                || allow_missing && current.is_none()
                || has_recorded_cache_repair(tx, index, entry)?,
            "Release support at {} changed. Keep the recovery files and ask the operator to restore this path from its verified release before starting Home again.",
            tx.data_dir.join(&entry.path).display()
        );
        if current != entry.original {
            anyhow::ensure!(
                state(&scratch(tx, index, false))? == entry.original,
                "release support rollback changed at {}. Keep recovery files for operator repair.",
                scratch(tx, index, false).display()
            );
        }
    }
    Ok(())
}

pub(super) fn restore(tx: &InstallTransaction, entries: &[Entry]) -> anyhow::Result<()> {
    validate_restore(tx, entries)?;
    for (index, entry) in entries.iter().enumerate() {
        let destination = tx.data_dir.join(&entry.path);
        if state(&destination)? == entry.original {
            continue;
        }
        let recorded = scratch(tx, index, false);
        if entry.original.is_some()
            && state(&recorded)? == entry.original
            && cache_drift_only(&destination, &recorded)?
        {
            repair_cache_tree(&destination, &recorded)?;
        } else {
            remove(&destination)?;
            if entry.original.is_some() {
                let prepared = delivery(tx, index, false);
                // Preserve compatibility with journals made before delivery copies.
                fs::rename(
                    if fs::symlink_metadata(&prepared).is_ok() {
                        prepared
                    } else {
                        recorded
                    },
                    &destination,
                )?;
            }
        }
        sync_directory(destination.parent().unwrap())?;
    }
    require_original(tx, entries)
}

fn repair_cache_tree(current: &Path, recorded: &Path) -> anyhow::Result<()> {
    if state(current)? == state(recorded)? {
        return Ok(());
    }
    anyhow::ensure!(
        cache_drift_only(current, recorded)?,
        "Release support changed at {}. Keep recovery files for operator repair.",
        current.display()
    );
    if current
        .file_name()
        .is_some_and(|name| name == "__pycache__")
    {
        remove(current)?;
        if recorded.exists() {
            copy_tree(recorded, current)?;
        }
        return sync_directory(current.parent().unwrap());
    }
    let mut names = BTreeSet::new();
    for directory in [current, recorded] {
        for child in fs::read_dir(directory)? {
            names.insert(child?.file_name());
        }
    }
    for name in names {
        repair_cache_tree(&current.join(&name), &recorded.join(&name))?;
    }
    Ok(())
}

/// The restart owner has proved its Home process gone. Repair only cache drift
/// against the requested, exact journal identity before accepting readiness.
pub(super) fn repair_installed(
    tx: &InstallTransaction,
    entries: &[Entry],
    previous: bool,
) -> anyhow::Result<()> {
    let mut repairs = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let expected = if previous {
            &entry.original
        } else {
            &entry.candidate
        };
        let destination = tx.data_dir.join(&entry.path);
        if state(&destination)? == *expected {
            continue;
        }
        let source = scratch(tx, index, !previous);
        anyhow::ensure!(expected.is_some() && state(&source)? == *expected
            && cache_drift_only(&destination, &source)?,
            "Release support at {} needs repair. Keep the recovery files and restore this path from its verified release before starting Home again.", destination.display());
        repairs.push((source, destination));
    }
    for (source, destination) in repairs {
        repair_cache_tree(&destination, &source)?;
    }
    require_installed(tx, entries, previous)
}

pub(super) fn cleanup(tx: &InstallTransaction, journal: &Journal) -> anyhow::Result<()> {
    validate_scratch(tx, journal)?;
    remove(&tx.data_dir.join(SCRATCH))?;
    sync_directory(&tx.data_dir)
}
