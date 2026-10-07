#!/usr/bin/env node

/**
 * Storage Audit Tool (CLI) - storage_audit.js
 * Modul Native: fs, path, crypto, readline
 * Dependensi Eksternal: ZERO (Tanpa npm install)
 *
 * Memenuhi Kebutuhan Sistem Audit Penyimpanan:
 * - STG-01: Recursive Scan
 * - STG-02: Duplicate Detection
 * - STG-03: Giant File Flagging (>= 2 MB / 2.048 KB)
 * - STG-04: Terminal Report (Terstruktur di stdout)
 * - STG-05: Safe Cleanup Confirmation (Y/N interaktif)
 * - STG-06: Zero-Dependency Portability
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// Konfigurasi Ambang Batas
const GIANT_FILE_THRESHOLD_BYTES = 2 * 1024 * 1024; // 2 MB = 2.048 KB = 2.097.152 bytes

// Warna Terminal ANSI
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m'
};

// Format ukuran byte ke string rapi
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}

function formatKB(bytes) {
  return `${(bytes / 1024).toLocaleString('id-ID', { maximumFractionDigits: 1 })} KB`;
}

function formatMB(bytes) {
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

// Menghitung SHA-256 dari file
function calculateSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', err => reject(err));
  });
}

// Menentukan path target yang akan dipindai
function resolveTargetDirectory() {
  const cliArg = process.argv[2];
  if (cliArg) {
    const resolved = path.resolve(cliArg);
    if (fs.existsSync(resolved)) return resolved;
  }

  const defaultNamed = path.resolve('Bahan Latihan P12');
  if (fs.existsSync(defaultNamed)) return defaultNamed;

  const parentNamed = path.resolve('..', 'Bahan Latihan P12');
  if (fs.existsSync(parentNamed)) return parentNamed;

  // Fallback ke folder kerja saat ini
  return process.cwd();
}

// STG-01: Memindai folder target secara rekursif
async function scanDirectory(dirPath, scriptFilesToIgnore) {
  const fileEntries = [];

  async function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (err) {
      console.error(`${colors.red}[ERROR] Gagal membaca direktori: ${currentDir} (${err.message})${colors.reset}`);
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile()) {
        // Abaikan file skrip audit itu sendiri
        const lowerName = entry.name.toLowerCase();
        if (lowerName === 'storage_audit.js' || lowerName === 'storage_audit.py') {
          continue;
        }

        try {
          const stat = fs.statSync(fullPath);
          const hash = await calculateSha256(fullPath);
          const isTmp = entry.name.toLowerCase().endsWith('.tmp');

          fileEntries.push({
            name: entry.name,
            fullPath: fullPath,
            relativePath: path.relative(dirPath, fullPath) || entry.name,
            size: stat.size,
            hash: hash,
            isTmp: isTmp,
            mtime: stat.mtimeMs
          });
        } catch (err) {
          console.error(`${colors.yellow}[WARNING] Gagal membaca file: ${entry.name} (${err.message})${colors.reset}`);
        }
      }
    }
  }

  await walk(dirPath);
  return fileEntries;
}

// Heuristik untuk menentukan file mana yang merupakan "File Asli" vs "Salinan Duplikat"
function pickOriginalFile(filesInGroup) {
  // Berikan skor penalti untuk indikator nama salinan
  function scoreFilename(file) {
    let score = 0;
    const name = file.name.toLowerCase();

    // Penalti untuk kata-kata copy / salinan / backup / versi
    if (name.includes('copy') || name.includes('salinan')) score += 100;
    if (name.includes('backup')) score += 100;
    if (/\(\d+\)/.test(name)) score += 100;
    if (name.includes('_copy')) score += 80;
    if (name.includes('_v2') || name.includes('_edit') || name.includes('_fix') || name.includes('_final')) score += 50;

    // Nama yang lebih panjang biasanya merupakan hasil modifikasi/salinan
    score += file.name.length;
    return score;
  }

  const sorted = [...filesInGroup].sort((a, b) => {
    const scoreDiff = scoreFilename(a) - scoreFilename(b);
    if (scoreDiff !== 0) return scoreDiff;
    return a.mtime - b.mtime; // Utamakan yang lebih awal dibuat jika skor sama
  });

  return {
    original: sorted[0],
    duplicates: sorted.slice(1)
  };
}

// STG-04: Menampilkan Laporan di Terminal
function displayReport(targetDir, allFiles, giantFiles, duplicateGroups, tmpFiles) {
  const totalSizeBytes = allFiles.reduce((acc, f) => acc + f.size, 0);

  // Hitung potensi penghematan
  let duplicateSavingsBytes = 0;
  let totalDuplicateFilesCount = 0;

  for (const group of duplicateGroups) {
    const dupCount = group.duplicates.length;
    totalDuplicateFilesCount += dupCount;
    duplicateSavingsBytes += dupCount * group.fileSize;
  }

  const tmpSavingsBytes = tmpFiles.reduce((acc, f) => acc + f.size, 0);
  const totalPotentialSavings = duplicateSavingsBytes + tmpSavingsBytes;

  console.log('\n' + colors.cyan + colors.bold + '=================================================================================' + colors.reset);
  console.log(colors.cyan + colors.bold + '              STORAGE AUDIT & OPTIMIZATION REPORT (CLI)                          ' + colors.reset);
  console.log(colors.cyan + colors.bold + '=================================================================================' + colors.reset);
  console.log(`${colors.bold}Target Folder :${colors.reset} ${targetDir}`);
  console.log(`${colors.bold}Total File    :${colors.reset} ${colors.green}${allFiles.length}${colors.reset} file ditemukan`);
  console.log(`${colors.bold}Total Ukuran  :${colors.reset} ${formatBytes(totalSizeBytes)} (${totalSizeBytes.toLocaleString('id-ID')} bytes)`);
  console.log(colors.dim + '---------------------------------------------------------------------------------' + colors.reset);

  // STG-03: Bagian File Raksasa (Giant Files)
  console.log(`\n${colors.yellow}${colors.bold}[STG-03] DAFTAR FILE RAKSASA (Ambang Batas >= 2 MB / 2.048 KB)${colors.reset}`);
  console.log(`${colors.dim}Ditemukan: ${giantFiles.length} file raksasa${colors.reset}\n`);

  if (giantFiles.length === 0) {
    console.log(`  ${colors.green}✔ Tidak ada file yang melebihi 2 MB.${colors.reset}`);
  } else {
    console.log(`  ${colors.bold}${'No.'.padEnd(4)} ${'Ukuran (MB / KB)'.padEnd(24)} ${'Nama File'.padEnd(45)}${colors.reset}`);
    console.log(`  ${'-'.repeat(75)}`);
    giantFiles.forEach((file, idx) => {
      const sizeStr = `${formatMB(file.size)} (${formatKB(file.size)})`;
      console.log(`  ${colors.cyan}${(idx + 1).toString().padEnd(4)}${colors.reset} ${colors.yellow}${sizeStr.padEnd(24)}${colors.reset} ${file.relativePath}`);
    });
  }

  // STG-02: Bagian Kelompok Duplikat (Duplicate Groups)
  console.log(`\n${colors.magenta}${colors.bold}[STG-02] DAFTAR KELOMPOK DUPLIKAT (Berdasarkan SHA-256 Identik)${colors.reset}`);
  console.log(`${colors.dim}Ditemukan: ${duplicateGroups.length} kelompok duplikat (${totalDuplicateFilesCount} file salinan)${colors.reset}\n`);

  if (duplicateGroups.length === 0) {
    console.log(`  ${colors.green}✔ Tidak ada file duplikat.${colors.reset}`);
  } else {
    duplicateGroups.forEach((group, idx) => {
      console.log(`  ${colors.bold}${colors.blue}Grup #${idx + 1}${colors.reset} [Ukuran: ${formatBytes(group.fileSize)} per file | Hash: ${colors.dim}${group.hash.substring(0, 16)}...${colors.reset}]`);
      console.log(`    ${colors.green}● [SIMPAN/ASLI] :${colors.reset} ${group.original.relativePath}`);
      group.duplicates.forEach(dup => {
        console.log(`    ${colors.red}✗ [SALINAN]     :${colors.reset} ${dup.relativePath}`);
      });
      console.log('');
    });
  }

  // File Sampah .tmp (jika ada)
  if (tmpFiles.length > 0) {
    console.log(`${colors.red}${colors.bold}[JUNK] FILE SAMPAH TEMPORER (.tmp)${colors.reset}`);
    tmpFiles.forEach((tmp, idx) => {
      console.log(`  ${idx + 1}. ${tmp.relativePath} (${formatBytes(tmp.size)})`);
    });
    console.log('');
  }

  // Ringkasan Estimasi Hemat Ruang
  console.log(colors.cyan + colors.bold + '=================================================================================' + colors.reset);
  console.log(`${colors.bold}RINGKASAN ESTIMASI PENGHEMATAN RUANG PENYIMPANAN:${colors.reset}`);
  console.log(`  ● Salinan Duplikat yang Dapat Dihapus : ${colors.yellow}${totalDuplicateFilesCount} file${colors.reset}`);
  if (tmpFiles.length > 0) {
    console.log(`  ● File Sampah .tmp                    : ${colors.yellow}${tmpFiles.length} file${colors.reset}`);
  }
  console.log(`  ● Total Ruang yang Dapat Dihemat      : ${colors.green}${colors.bold}${formatBytes(totalPotentialSavings)}${colors.reset} (${totalPotentialSavings.toLocaleString('id-ID')} bytes)`);
  console.log(colors.cyan + colors.bold + '=================================================================================' + colors.reset);

  return {
    totalDuplicateFilesCount,
    totalPotentialSavings
  };
}

// STG-05: Konfirmasi Pembersihan Aman Secara Interaktif
async function promptAndCleanup(duplicateGroups, tmpFiles) {
  const filesToDelete = [];

  for (const group of duplicateGroups) {
    for (const dup of group.duplicates) {
      filesToDelete.push(dup);
    }
  }

  for (const tmp of tmpFiles) {
    filesToDelete.push(tmp);
  }

  if (filesToDelete.length === 0) {
    console.log(`\n${colors.green}Sistem penyimpanan bersih. Tidak ada file duplikat atau sampah yang perlu dibersihkan.${colors.reset}\n`);
    return;
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const question = `\n${colors.bold}${colors.yellow}Apakah kamu ingin menghapus file duplikat yang tidak terpakai? (Y/N): ${colors.reset}`;

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      const trimmed = answer.trim().toUpperCase();

      if (trimmed === 'Y') {
        console.log(`\n${colors.cyan}[INFO] Memulai proses pembersihan file duplikat & sampah...${colors.reset}`);
        let deletedCount = 0;
        let deletedBytes = 0;

        for (const file of filesToDelete) {
          try {
            fs.unlinkSync(file.fullPath);
            deletedCount++;
            deletedBytes += file.size;
            console.log(`  ${colors.green}[BERHASIL DIHAPUS]${colors.reset} ${file.relativePath} (${formatBytes(file.size)})`);
          } catch (err) {
            console.error(`  ${colors.red}[GAGAL DIHAPUS]${colors.reset} ${file.relativePath}: ${err.message}`);
          }
        }

        console.log(`\n${colors.green}${colors.bold}✔ PEMBERSIHAN SELESAI!${colors.reset}`);
        console.log(`  Total file dihapus : ${colors.bold}${deletedCount} file${colors.reset}`);
        console.log(`  Ruang dibebaskan   : ${colors.green}${colors.bold}${formatBytes(deletedBytes)}${colors.reset} (${deletedBytes.toLocaleString('id-ID')} bytes)\n`);
      } else {
        console.log(`\n${colors.blue}[AMAN] Pembersihan dibatalkan (N). Tidak ada file yang diubah atau dihapus.${colors.reset}\n`);
      }
      resolve();
    });
  });
}

// Fungsi Utama
async function main() {
  const targetDir = resolveTargetDirectory();

  // Set file skrip sendiri agar tidak ikut di-hash/di-audit/dihapus
  const scriptFilesToIgnore = new Set([
    path.resolve(__filename),
    path.resolve(path.join(process.cwd(), 'storage_audit.js')),
    path.resolve(path.join(process.cwd(), 'storage_audit.py'))
  ]);

  console.log(`${colors.cyan}[START] Memulai audit penyimpanan pada folder: ${targetDir}${colors.reset}`);

  // STG-01: Recursive Scan
  const allFiles = await scanDirectory(targetDir, scriptFilesToIgnore);

  if (allFiles.length === 0) {
    console.log(`${colors.yellow}[INFO] Folder kosong atau tidak ada file yang dapat dipindai.${colors.reset}`);
    return;
  }

  // STG-03: Giant File Flagging (>= 2 MB)
  const giantFiles = allFiles
    .filter(f => f.size >= GIANT_FILE_THRESHOLD_BYTES)
    .sort((a, b) => b.size - a.size); // Urutkan dari yang terbesar

  // STG-02: Duplicate Detection
  const hashMap = new Map();
  for (const file of allFiles) {
    if (!hashMap.has(file.hash)) {
      hashMap.set(file.hash, []);
    }
    hashMap.get(file.hash).push(file);
  }

  const duplicateGroups = [];
  for (const [hash, files] of hashMap.entries()) {
    if (files.length > 1) {
      const { original, duplicates } = pickOriginalFile(files);
      duplicateGroups.push({
        hash,
        fileSize: files[0].size,
        original,
        duplicates
      });
    }
  }

  // Urutkan grup duplikat berdasarkan ukuran file terbesar
  duplicateGroups.sort((a, b) => (b.fileSize * b.duplicates.length) - (a.fileSize * a.duplicates.length));

  // Kumpulkan file .tmp yang bukan bagian dari salinan duplikat
  const dupPaths = new Set();
  duplicateGroups.forEach(g => {
    dupPaths.add(g.original.fullPath);
    g.duplicates.forEach(d => dupPaths.add(d.fullPath));
  });
  const tmpFiles = allFiles.filter(f => f.isTmp && !dupPaths.has(f.fullPath));

  // STG-04: Tampilkan Laporan di Terminal
  displayReport(targetDir, allFiles, giantFiles, duplicateGroups, tmpFiles);

  // STG-05: Safe Cleanup Confirmation
  await promptAndCleanup(duplicateGroups, tmpFiles);
}

main().catch(err => {
  console.error(`${colors.red}[FATAL ERROR] ${err.stack || err.message}${colors.reset}`);
  process.exit(1);
});
