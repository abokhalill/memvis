// SPDX-License-Identifier: Apache-2.0

// /proc/<pid>/maps parser for shared region detection across processes.
// identifies shared mappings by (dev_major, dev_minor, inode) tuples.

use std::collections::HashMap;
use std::fs;
use std::io;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DevInode {
    pub dev_major: u32,
    pub dev_minor: u32,
    pub inode: u64,
}

#[derive(Debug, Clone)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub perms: [u8; 4],
    pub offset: u64,
    pub dev_inode: DevInode,
    pub path: String,
}

impl MapEntry {
    pub fn is_writable(&self) -> bool {
        self.perms[1] == b'w'
    }

    pub fn is_shared(&self) -> bool {
        self.perms[3] == b's'
    }

    pub fn size(&self) -> u64 {
        self.end - self.start
    }
}

/// parse a single line of /proc/<pid>/maps
/// format: start-end perms offset dev inode pathname
fn parse_map_line(line: &str) -> Option<MapEntry> {
    let mut parts = line.splitn(6, char::is_whitespace);

    let range = parts.next()?;
    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;

    let perms_s = parts.next()?;
    if perms_s.len() < 4 {
        return None;
    }
    let mut perms = [0u8; 4];
    perms.copy_from_slice(&perms_s.as_bytes()[..4]);

    let offset_s = parts.next()?;
    let offset = u64::from_str_radix(offset_s, 16).ok()?;

    let dev_s = parts.next()?;
    let (maj_s, min_s) = dev_s.split_once(':')?;
    let dev_major = u32::from_str_radix(maj_s, 16).ok()?;
    let dev_minor = u32::from_str_radix(min_s, 16).ok()?;

    let inode_s = parts.next()?.trim();
    let inode: u64 = inode_s.parse().ok()?;

    let path = parts.next().unwrap_or("").trim().to_string();

    Some(MapEntry {
        start,
        end,
        perms,
        offset,
        dev_inode: DevInode {
            dev_major,
            dev_minor,
            inode,
        },
        path,
    })
}

/// read and parse /proc/<pid>/maps
pub fn read_maps(pid: u32) -> io::Result<Vec<MapEntry>> {
    let content = fs::read_to_string(format!("/proc/{}/maps", pid))?;
    Ok(content
        .lines()
        .filter_map(parse_map_line)
        .collect())
}

/// a shared region found in two or more processes
#[derive(Debug, Clone)]
pub struct SharedRegion {
    pub dev_inode: DevInode,
    pub path: String,
    /// (pid, start_addr, end_addr) for each process mapping this region
    pub mappings: Vec<(u32, u64, u64)>,
}

/// detect shared regions between a set of processes by matching (dev, inode).
/// filters out anonymous mappings (inode == 0) and non-shared/non-file-backed regions.
pub fn detect_shared_regions(pids: &[u32]) -> io::Result<Vec<SharedRegion>> {
    // key: DevInode -> (path, Vec<(pid, start, end)>)
    let mut index: HashMap<DevInode, (String, Vec<(u32, u64, u64)>)> = HashMap::new();

    for &pid in pids {
        let entries = match read_maps(pid) {
            Ok(e) => e,
            Err(_) => continue, // process may have exited
        };
        for e in entries {
            if e.dev_inode.inode == 0 {
                continue; // anonymous mapping
            }
            let entry = index
                .entry(e.dev_inode.clone())
                .or_insert_with(|| (e.path.clone(), Vec::new()));
            entry.1.push((pid, e.start, e.end));
        }
    }

    // only keep regions present in 2+ distinct pids
    let shared: Vec<SharedRegion> = index
        .into_iter()
        .filter_map(|(di, (path, mappings))| {
            let mut seen_pids: Vec<u32> = mappings.iter().map(|m| m.0).collect();
            seen_pids.sort_unstable();
            seen_pids.dedup();
            if seen_pids.len() >= 2 {
                Some(SharedRegion {
                    dev_inode: di,
                    path,
                    mappings,
                })
            } else {
                None
            }
        })
        .collect();

    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_map_line_file_backed() {
        let line = "7f1234000000-7f1234001000 r-xp 00000000 08:01 12345678                   /usr/lib/libc.so.6";
        let entry = parse_map_line(line).unwrap();
        assert_eq!(entry.start, 0x7f1234000000);
        assert_eq!(entry.end, 0x7f1234001000);
        assert_eq!(entry.perms, *b"r-xp");
        assert_eq!(entry.offset, 0);
        assert_eq!(entry.dev_inode.dev_major, 8);
        assert_eq!(entry.dev_inode.dev_minor, 1);
        assert_eq!(entry.dev_inode.inode, 12345678);
        assert_eq!(entry.path, "/usr/lib/libc.so.6");
        assert!(!entry.is_writable());
        assert!(!entry.is_shared());
    }

    #[test]
    fn test_parse_map_line_shared() {
        let line = "7f0000000000-7f0000100000 rw-s 00000000 00:05 99999                      /dev/shm/rtmap_ctl_1234";
        let entry = parse_map_line(line).unwrap();
        assert!(entry.is_writable());
        assert!(entry.is_shared());
        assert_eq!(entry.dev_inode.inode, 99999);
        assert!(entry.path.contains("rtmap_ctl"));
    }

    #[test]
    fn test_parse_map_line_anonymous() {
        let line = "7ffc00000000-7ffc00021000 rw-p 00000000 00:00 0                          [stack]";
        let entry = parse_map_line(line).unwrap();
        assert_eq!(entry.dev_inode.inode, 0);
        assert_eq!(entry.path, "[stack]");
    }

    #[test]
    fn test_parse_map_line_no_path() {
        let line = "7f0000200000-7f0000300000 rw-p 00000000 00:00 0";
        let entry = parse_map_line(line).unwrap();
        assert_eq!(entry.dev_inode.inode, 0);
        assert_eq!(entry.path, "");
    }

    #[test]
    fn test_shared_region_detection_logic() {
        // simulate two processes with overlapping inode
        let di = DevInode { dev_major: 0, dev_minor: 5, inode: 42 };
        let di2 = DevInode { dev_major: 8, dev_minor: 1, inode: 100 };

        let mut index: HashMap<DevInode, (String, Vec<(u32, u64, u64)>)> = HashMap::new();
        // shared by pid 10 and 20
        index.entry(di.clone()).or_insert_with(|| ("/dev/shm/foo".into(), Vec::new()))
            .1.push((10, 0x1000, 0x2000));
        index.entry(di).or_insert_with(|| ("/dev/shm/foo".into(), Vec::new()))
            .1.push((20, 0x3000, 0x4000));
        // only pid 10
        index.entry(di2).or_insert_with(|| ("/usr/lib/bar.so".into(), Vec::new()))
            .1.push((10, 0x5000, 0x6000));

        let shared: Vec<SharedRegion> = index
            .into_iter()
            .filter_map(|(di, (path, mappings))| {
                let mut seen: Vec<u32> = mappings.iter().map(|m| m.0).collect();
                seen.sort_unstable();
                seen.dedup();
                if seen.len() >= 2 {
                    Some(SharedRegion { dev_inode: di, path, mappings })
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].dev_inode.inode, 42);
        assert_eq!(shared[0].mappings.len(), 2);
    }

    #[test]
    fn test_read_maps_self() {
        // /proc/self/maps should always be readable
        let pid = std::process::id();
        let maps = read_maps(pid).unwrap();
        assert!(!maps.is_empty(), "self maps should have entries");
        // should contain at least one entry with our executable
        let has_exe = maps.iter().any(|e| e.perms[2] == b'x');
        assert!(has_exe, "should have at least one executable mapping");
    }
}
