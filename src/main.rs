#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use blake2::{Blake2b512, Blake2s256};
use crc::Crc;
use crc32fast::Hasher as Crc32Hasher;
use eframe::egui;
use serde::{Deserialize, Serialize};
use md5::Context as Md5Context;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha384, Sha512};
use sha3::{Digest as Sha3Digest, Sha3_256, Sha3_512};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use twox_hash::XxHash64;
use std::hash::Hasher;

const ZH_FONT_DATA: &[u8] = include_bytes!("../fonts/zh.ttf");
const ICON_DATA: &[u8] = include_bytes!("../icon/icon.png");

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake2b,
    Blake2s,
    Sha1,
    Md5,
    Crc32,
    Crc64,
    XxHash64,
}

impl HashAlgorithm {
    fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_512 => "SHA3-512",
            Self::Blake2b => "BLAKE2b",
            Self::Blake2s => "BLAKE2s",
            Self::Sha1 => "SHA-1",
            Self::Md5 => "MD5",
            Self::Crc32 => "CRC32",
            Self::Crc64 => "CRC64",
            Self::XxHash64 => "xxHash64",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::Sha256 => "广泛使用的安全哈希算法，输出256位（32字节）。",
            Self::Sha384 => "SHA-2家族的一员，输出384位，常用于需要比SHA-256更高安全性的场合。",
            Self::Sha512 => "SHA-2家族中最强的算法，输出512位，在64位系统上性能优异。",
            Self::Sha3_256 => "SHA-3标准算法，基于Keccak，提供极高的安全性和抗攻击能力。",
            Self::Sha3_512 => "SHA-3标准中最强的变体，输出512位。",
            Self::Blake2b => "比SHA-3更快的安全哈希算法，针对64位平台优化。",
            Self::Blake2s => "针对8位到32位平台优化的BLAKE2版本。",
            Self::Sha1 => "较旧的算法，现已不推荐用于安全目的，但仍广泛用于完整性校验。",
            Self::Md5 => "经典的128位哈希算法，速度极快，但不具备安全性，仅用于基本校验。",
            Self::Crc32 => "循环冗余校验，速度极快，主要用于检测数据传输或存储中的意外错误。",
            Self::Crc64 => "64位循环冗余校验，比CRC32提供更低的碰撞概率。",
            Self::XxHash64 => "极其快速的非加密哈希算法，具有极高的吞吐量和极佳的散列质量。",
        }
    }
}

fn normalize_input_path(input: &str) -> String {
    let filtered: String = input
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{202A}' | '\u{202B}' | '\u{202D}' | '\u{202E}' | '\u{200E}' | '\u{200F}'
            )
        })
        .collect();

    let trimmed = filtered.trim();
    let trimmed = trimmed.trim_matches('"').trim_matches('“').trim_matches('”');
    trimmed.to_string()
}

fn compute_hash_with_callback<F>(algo: &HashAlgorithm, path: &str, mut on_progress: F) -> io::Result<String>
where
    F: FnMut(u8),
{
    let file = File::open(normalize_input_path(path))?;
    let metadata = file.metadata()?;
    let total_size = metadata.len();

    let mut reader = BufReader::new(file);
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut processed: u64 = 0;
    let mut last_percent: u8 = 0;

    enum HashState {
        Sha1(Sha1),
        Sha256(Sha256),
        Sha384(Sha384),
        Sha512(Sha512),
        Sha3_256(Sha3_256),
        Sha3_512(Sha3_512),
        Blake2b(Blake2b512),
        Blake2s(Blake2s256),
        Md5(Md5Context),
        Crc32(Crc32Hasher),
        Crc64(u64),
        XxHash64(XxHash64),
    }

    let crc64_algo = Crc::<u64>::new(&crc::CRC_64_XZ);

    let mut state = match algo {
        HashAlgorithm::Sha1 => HashState::Sha1(Sha1::new()),
        HashAlgorithm::Sha256 => HashState::Sha256(Sha256::new()),
        HashAlgorithm::Sha384 => HashState::Sha384(Sha384::new()),
        HashAlgorithm::Sha512 => HashState::Sha512(Sha512::new()),
        HashAlgorithm::Sha3_256 => HashState::Sha3_256(Sha3_256::new()),
        HashAlgorithm::Sha3_512 => HashState::Sha3_512(Sha3_512::new()),
        HashAlgorithm::Blake2b => HashState::Blake2b(Blake2b512::new()),
        HashAlgorithm::Blake2s => HashState::Blake2s(Blake2s256::new()),
        HashAlgorithm::Md5 => HashState::Md5(Md5Context::new()),
        HashAlgorithm::Crc32 => HashState::Crc32(Crc32Hasher::new()),
        HashAlgorithm::Crc64 => HashState::Crc64(crc64_algo.algorithm.init),
        HashAlgorithm::XxHash64 => HashState::XxHash64(XxHash64::default()),
    };

    loop {
        let read_bytes = reader.read(&mut buffer)?;
        if read_bytes == 0 {
            break;
        }
        let chunk = &buffer[..read_bytes];

        match &mut state {
            HashState::Sha1(h) => {
                use Sha1Digest as _;
                h.update(chunk);
            }
            HashState::Sha256(h) => {
                use Sha2Digest as _;
                h.update(chunk);
            }
            HashState::Sha384(h) => {
                use Sha2Digest as _;
                h.update(chunk);
            }
            HashState::Sha512(h) => {
                use Sha2Digest as _;
                h.update(chunk);
            }
            HashState::Sha3_256(h) => {
                use Sha3Digest as _;
                h.update(chunk);
            }
            HashState::Sha3_512(h) => {
                use Sha3Digest as _;
                h.update(chunk);
            }
            HashState::Blake2b(h) => {
                blake2::digest::Update::update(h, chunk);
            }
            HashState::Blake2s(h) => {
                blake2::digest::Update::update(h, chunk);
            }
            HashState::Md5(h) => {
                h.consume(chunk);
            }
            HashState::Crc32(h) => {
                h.update(chunk);
            }
            HashState::Crc64(h) => {
                let mut digest = crc64_algo.digest_with_initial(*h);
                digest.update(chunk);
                *h = digest.finalize() ^ crc64_algo.algorithm.xorout;
            }
            HashState::XxHash64(h) => {
                h.write(chunk);
            }
        }
        processed += read_bytes as u64;

        if total_size > 0 {
            let percent =
                ((processed as f64 / total_size as f64) * 100.0).min(100.0).floor() as u8;
            if percent != last_percent {
                last_percent = percent;
                on_progress(percent);
            }
        }
    }

    let hex = match state {
        HashState::Sha1(h) => {
            let result = h.finalize();
            let mut hex = String::with_capacity(40);
            for byte in result {
                hex.push_str(&format!("{:02x}", byte));
            }
            hex
        }
        HashState::Sha256(h) => {
            let result = h.finalize();
            let mut hex = String::with_capacity(64);
            for byte in result {
                hex.push_str(&format!("{:02x}", byte));
            }
            hex
        }
        HashState::Sha384(h) => {
            let result = h.finalize();
            let mut hex = String::with_capacity(96);
            for byte in result {
                hex.push_str(&format!("{:02x}", byte));
            }
            hex
        }
        HashState::Sha512(h) => {
            let result = h.finalize();
            let mut hex = String::with_capacity(128);
            for byte in result {
                hex.push_str(&format!("{:02x}", byte));
            }
            hex
        }
        HashState::Sha3_256(h) => {
            let result = h.finalize();
            let mut hex = String::with_capacity(64);
            for byte in result {
                hex.push_str(&format!("{:02x}", byte));
            }
            hex
        }
        HashState::Sha3_512(h) => {
            let result = h.finalize();
            let mut hex = String::with_capacity(128);
            for byte in result {
                hex.push_str(&format!("{:02x}", byte));
            }
            hex
        }
        HashState::Blake2b(h) => {
            use blake2::digest::FixedOutput;
            let result = h.finalize_fixed();
            let mut hex = String::with_capacity(128);
            for byte in result {
                hex.push_str(&format!("{:02x}", byte));
            }
            hex
        }
        HashState::Blake2s(h) => {
            use blake2::digest::FixedOutput;
            let result = h.finalize_fixed();
            let mut hex = String::with_capacity(64);
            for byte in result {
                hex.push_str(&format!("{:02x}", byte));
            }
            hex
        }
        HashState::Md5(h) => {
            let result = h.compute();
            format!("{:032x}", result)
        }
        HashState::Crc32(h) => {
            let value = h.finalize();
            format!("{:08x}", value)
        }
        HashState::Crc64(h) => {
            format!("{:016x}", h ^ crc64_algo.algorithm.xorout)
        }
        HashState::XxHash64(h) => {
            format!("{:016x}", h.finish())
        }
    };

    Ok(hex)
}

#[derive(Clone, Serialize, Deserialize)]
struct FileEntry {
    path: String,
    name: String,
    size: u64,
    extension: String,
    modified: String,
    duration: Option<String>,
    algo: HashAlgorithm,
    #[serde(skip)]
    hash: Option<String>,
    #[serde(skip)]
    error: Option<String>,
    #[serde(skip)]
    progress: f32, // 0.0 to 1.0
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum SortKey {
    Name,
    Size,
    Modified,
    Status,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum SortOrder {
    Asc,
    Desc,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct HashApp {
    algo: HashAlgorithm,
    #[serde(skip)]
    active_tasks: Arc<AtomicUsize>,
    #[serde(skip)]
    files: Arc<Mutex<Vec<FileEntry>>>,
    #[serde(skip)]
    selected_index: Option<usize>,
    #[serde(skip)]
    expected_input: String,
    #[serde(skip)]
    verify_result: Option<bool>,
    #[serde(skip)]
    show_about: bool,
    #[serde(skip)]
    toast_text: Option<String>,
    #[serde(skip)]
    toast_start_time: Option<Instant>,
    auto_calculate: bool,
    filter_query: String,
    sort_key: SortKey,
    sort_order: SortOrder,
}

fn format_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{} Bytes", bytes)
    }
}

impl Default for HashApp {
    fn default() -> Self {
        Self {
            algo: HashAlgorithm::Sha256,
            active_tasks: Arc::new(AtomicUsize::new(0)),
            files: Arc::new(Mutex::new(Vec::new())),
            selected_index: None,
            expected_input: String::new(),
            verify_result: None,
            show_about: false,
            toast_text: None,
            toast_start_time: None,
            auto_calculate: true,
            filter_query: String::new(),
            sort_key: SortKey::Name,
            sort_order: SortOrder::Asc,
        }
    }
}

impl HashApp {
    fn show_toast(&mut self, text: impl Into<String>) {
        self.toast_text = Some(text.into());
        self.toast_start_time = Some(Instant::now());
    }

    fn trigger_copy(&mut self, ui: &mut egui::Ui, text: String, _label: &str) {
        ui.output_mut(|o| o.copied_text = text);
        // 触发复制成功回调逻辑
        self.show_toast("哈希值已复制到剪贴板");
    }

    fn add_files(&mut self, paths: Vec<std::path::PathBuf>) {
        let mut new_entries = Vec::new();
        for path in paths {
            let metadata = std::fs::metadata(&path).ok();
            let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = metadata.as_ref()
                .and_then(|m| m.modified().ok())
                .map(|t| {
                    let datetime: chrono::DateTime<chrono::Local> = t.into();
                    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
                })
                .unwrap_or_else(|| "未知".to_string());
            
            let name = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("未知文件")
                .to_string();
            
            let extension = path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_uppercase();

            if let Some(s) = path.to_str() {
                new_entries.push(FileEntry {
                    path: s.to_string(),
                    name,
                    size,
                    extension,
                    modified,
                    duration: None,
                    algo: self.algo,
                    hash: None,
                    error: None,
                    progress: 0.0,
                });
            }
        }
        
        if !new_entries.is_empty() {
            if let Ok(mut files) = self.files.lock() {
                files.extend(new_entries);
            }
            if self.auto_calculate {
                self.start_worker();
            }
        }
    }

    fn start_worker(&mut self) {
        let max_concurrent = 4;
        let active_tasks = self.active_tasks.clone();
        
        if active_tasks.load(Ordering::SeqCst) >= max_concurrent {
            return;
        }

        let files_arc = self.files.clone();
        let active_tasks_clone = active_tasks.clone();

        thread::spawn(move || {
            loop {
                // 如果当前任务数已达上限，稍微等待后重试（或者直接退出，让下次 update 触发）
                if active_tasks_clone.load(Ordering::SeqCst) >= max_concurrent {
                    break;
                }

                // 1. 寻找下一个待处理文件
                let target_info = {
                    let mut files = files_arc.lock().unwrap();
                    files.iter_mut().enumerate()
                        .find(|(_, f)| f.hash.is_none() && f.error.is_none() && f.progress == 0.0)
                        .map(|(i, f)| {
                            f.progress = 0.001; // 标记为正在处理
                            (i, f.path.clone(), f.algo)
                        })
                };

                // 2. 如果没有待处理文件，退出循环
                let (index, path, algo) = match target_info {
                    Some(info) => info,
                    None => break,
                };

                // 3. 增加活跃任务数
                active_tasks_clone.fetch_add(1, Ordering::SeqCst);

                // 4. 为该文件单独开一个线程计算
                let files_inner = files_arc.clone();
                let active_tasks_inner = active_tasks_clone.clone();
                
                thread::spawn(move || {
                    let start_time = Instant::now();
                    let files_for_callback = files_inner.clone();
                    
                    let res = compute_hash_with_callback(&algo, &path, |percent| {
                        if let Ok(mut files) = files_for_callback.lock() {
                            if let Some(target) = files.get_mut(index) {
                                target.progress = (percent as f32).min(100.0) / 100.0;
                            }
                        }
                    });

                    let duration = start_time.elapsed();
                    let duration_str = if duration.as_secs() > 0 {
                        format!("{:.2}s", duration.as_secs_f64())
                    } else {
                        format!("{}ms", duration.as_millis())
                    };

                    // 5. 更新文件列表中的结果
                    if let Ok(mut files) = files_inner.lock() {
                        if let Some(target) = files.get_mut(index) {
                            target.duration = Some(duration_str);
                            target.progress = 1.0;
                            match res {
                                Ok(hex) => {
                                    target.hash = Some(hex);
                                    target.error = None;
                                }
                                Err(err) => {
                                    target.hash = None;
                                    target.error = Some(err.to_string());
                                }
                            }
                        }
                    }

                    // 6. 减少活跃任务数
                    active_tasks_inner.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
    }
}

fn setup_custom_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    
    // Material Design 3 风格：大圆角
    style.visuals.window_rounding = 12.0.into();
    style.visuals.widgets.noninteractive.rounding = 8.0.into();
    style.visuals.widgets.inactive.rounding = 8.0.into();
    style.visuals.widgets.hovered.rounding = 8.0.into();
    style.visuals.widgets.active.rounding = 8.0.into();
    style.visuals.widgets.open.rounding = 8.0.into();

    // 交互颜色优化
    style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(233, 236, 239);
    style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(222, 226, 230);
    
    // 间距系统 (8px 基准)
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.window_margin = egui::Margin::same(16.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);

    ctx.set_style(style);
}

impl eframe::App for HashApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        setup_custom_style(ctx);
        
        let screen_size = ctx.screen_rect().size();
        let is_mobile = screen_size.x < 768.0;

        // 如果有活跃任务，请求持续重绘以更新进度条
        if self.active_tasks.load(Ordering::SeqCst) > 0 {
            ctx.request_repaint();
        }

        // 自动触发待处理文件的计算
        if self.auto_calculate {
            let has_pending = if let Ok(files) = self.files.lock() {
                files.iter().any(|f| f.hash.is_none() && f.error.is_none() && f.progress == 0.0)
            } else {
                false
            };
            if has_pending {
                self.start_worker();
            }
        }

        // 处理文件拖放
        ctx.input(|i| {
            if !i.raw.dropped_files.is_empty() {
                let paths: Vec<std::path::PathBuf> = i.raw.dropped_files.iter()
                    .filter_map(|f| f.path.clone())
                    .collect();
                if !paths.is_empty() {
                    self.add_files(paths);
                }
            }
        });

        // 顶部导航栏 - 专业深色或对比色
        egui::TopBottomPanel::top("top_bar")
            .frame(egui::Frame::none().fill(egui::Color32::from_gray(248)).inner_margin(egui::Margin::symmetric(20.0, 10.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("文件校验工具");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("关于").clicked() {
                            self.show_about = true;
                        }
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(egui::Color32::from_gray(255)).inner_margin(egui::Margin::same(20.0)))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        // 1. 算法选择区 - 采用卡片化布局
                egui::Frame::none()
                    .fill(egui::Color32::from_gray(250))
                    .rounding(12.0)
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(230)))
                    .inner_margin(egui::Margin::same(16.0))
                    .show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("选择算法类型:").strong().size(14.0));
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new(self.algo.description()).size(12.0).color(egui::Color32::from_rgb(108, 117, 125)));
                                
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.checkbox(&mut self.auto_calculate, "自动计算");
                                });
                            });
                            
                            ui.add_space(12.0);
                            
                            // 分组展示算法，更加直观
                            ui.horizontal_wrapped(|ui| {
                                let groups = [
                                    ("SHA-2 家族", vec![HashAlgorithm::Sha256, HashAlgorithm::Sha384, HashAlgorithm::Sha512]),
                                    ("SHA-3 家族", vec![HashAlgorithm::Sha3_256, HashAlgorithm::Sha3_512]),
                                    ("BLAKE 家族", vec![HashAlgorithm::Blake2b, HashAlgorithm::Blake2s]),
                                    ("快速/校验", vec![HashAlgorithm::XxHash64, HashAlgorithm::Crc32, HashAlgorithm::Crc64]),
                                    ("旧版标准", vec![HashAlgorithm::Sha1, HashAlgorithm::Md5]),
                                ];

                                for (group_name, algos) in groups {
                                    ui.vertical(|ui| {
                                        ui.label(egui::RichText::new(group_name).size(11.0).color(egui::Color32::from_rgb(150, 150, 150)));
                                        ui.horizontal(|ui| {
                                            for a in algos {
                                                let is_selected = self.algo == a;
                                                let btn_text = egui::RichText::new(a.name()).size(13.0);
                                                let btn = if is_selected {
                                                    egui::Button::new(btn_text.color(egui::Color32::WHITE))
                                                        .fill(egui::Color32::from_rgb(0, 120, 215))
                                                } else {
                                                    egui::Button::new(btn_text)
                                                        .fill(egui::Color32::from_rgb(240, 242, 245))
                                                };
                                                
                                                if ui.add(btn).on_hover_text(a.description()).clicked() {
                                                    self.algo = a;
                                                }
                                                ui.add_space(4.0);
                                            }
                                        });
                                    });
                                    ui.add_space(16.0);
                                }
                            });
                        });
                    });

                ui.add_space(15.0);

                // 2. 文件操作与搜索区
                ui.horizontal(|ui| {
                    let btn_select = ui.add(egui::Button::new(egui::RichText::new(" 导入文件 ").strong()).fill(egui::Color32::from_rgb(0, 120, 215)).stroke(egui::Stroke::NONE));
                    if btn_select.clicked() {
                        if let Some(paths) = rfd::FileDialog::new().pick_files() {
                            self.add_files(paths);
                        }
                    }

                    if ui.button(" 清空列表 ").clicked() {
                        if let Ok(mut files) = self.files.lock() {
                            files.clear();
                        }
                        self.selected_index = None;
                        self.expected_input.clear();
                        self.verify_result = None;
                    }

                    // 如果有待计算的文件，显示开始计算按钮
                    let has_pending = if let Ok(files) = self.files.lock() {
                        files.iter().any(|f| f.hash.is_none() && f.error.is_none() && f.progress == 0.0)
                    } else {
                        false
                    };
                    if has_pending {
                        let btn = egui::Button::new(egui::RichText::new(" 开始计算 ").color(egui::Color32::WHITE))
                            .fill(egui::Color32::from_rgb(40, 167, 69));
                        if ui.add(btn).clicked() {
                            self.start_worker();
                        }
                    }

                    ui.add_space(20.0);
                    ui.label("搜索:");
                    ui.add(egui::TextEdit::singleline(&mut self.filter_query).hint_text("按名称过滤..."));
                    
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        egui::ComboBox::from_label("排序")
                            .selected_text(match self.sort_key {
                                SortKey::Name => "名称",
                                SortKey::Size => "大小",
                                SortKey::Modified => "时间",
                                SortKey::Status => "状态",
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.sort_key, SortKey::Name, "名称");
                                ui.selectable_value(&mut self.sort_key, SortKey::Size, "大小");
                                ui.selectable_value(&mut self.sort_key, SortKey::Modified, "时间");
                                ui.selectable_value(&mut self.sort_key, SortKey::Status, "状态");
                            });
                        
                        if ui.button(if self.sort_order == SortOrder::Asc { "⬆" } else { "⬇" }).clicked() {
                            self.sort_order = match self.sort_order {
                                SortOrder::Asc => SortOrder::Desc,
                                SortOrder::Desc => SortOrder::Asc,
                            };
                        }
                    });
                });

                ui.add_space(10.0);

                // 3. 文件列表区 - 卡片列表
                let mut display_files: Vec<(usize, FileEntry)> = if let Ok(files) = self.files.lock() {
                    files.iter().cloned().enumerate().collect()
                } else {
                    Vec::new()
                };
                
                // 过滤
                if !self.filter_query.is_empty() {
                    let query = self.filter_query.to_lowercase();
                    display_files.retain(|(_, f)| f.name.to_lowercase().contains(&query));
                }
                
                // 排序
                display_files.sort_by(|(_, a), (_, b)| {
                    let res = match self.sort_key {
                        SortKey::Name => a.name.cmp(&b.name),
                        SortKey::Size => a.size.cmp(&b.size),
                        SortKey::Modified => a.modified.cmp(&b.modified),
                        SortKey::Status => {
                            let status_a = if a.hash.is_some() { 2 } else if a.error.is_some() { 0 } else { 1 };
                            let status_b = if b.hash.is_some() { 2 } else if b.error.is_some() { 0 } else { 1 };
                            status_a.cmp(&status_b)
                        }
                    };
                    if self.sort_order == SortOrder::Asc { res } else { res.reverse() }
                });

                ui.label(egui::RichText::new(format!("待处理文件 ({})", display_files.len())).strong().color(egui::Color32::from_gray(100)));
                ui.add_space(5.0);

                let scroll_height = ui.available_height() - 220.0;
                egui::ScrollArea::vertical()
                    .max_height(scroll_height.max(150.0))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (original_index, file) in display_files {
                            let is_selected = self.selected_index == Some(original_index);
                            let frame = egui::Frame::none()
                                .fill(if is_selected {
                                    egui::Color32::from_rgb(235, 245, 255) // 选中时淡蓝色
                                } else {
                                    egui::Color32::WHITE
                                })
                                .rounding(8.0)
                                .stroke(egui::Stroke::new(
                                    1.0,
                                    if is_selected {
                                        egui::Color32::from_rgb(0, 120, 215) // 选中时深蓝色边框
                                    } else {
                                        egui::Color32::from_gray(230) // 默认灰色边框
                                    }
                                ))
                                .inner_margin(egui::Margin::symmetric(16.0, 12.0));

                            let response = frame.show(ui, |ui| {
                                ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::PointingHand);
                                ui.horizontal(|ui| {
                                    let icon_text = match file.extension.as_str() {
                                        "EXE" | "MSI" => "💿",
                                        "ZIP" | "RAR" | "7Z" => "📦",
                                        "TXT" | "MD" | "LOG" => "📄",
                                        "JPG" | "PNG" | "GIF" => "🖼",
                                        _ => "📁",
                                    };
                                    
                                    ui.label(egui::RichText::new(icon_text).size(20.0));
                                    
                                    ui.vertical(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new(&file.name).strong().size(14.0).color(egui::Color32::from_rgb(33, 37, 41)));
                                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                ui.horizontal(|ui| {
                                                    if let Some(duration) = &file.duration {
                                                        ui.label(egui::RichText::new(duration).color(egui::Color32::from_rgb(40, 167, 69)).size(12.0));
                                                        ui.add_space(8.0);
                                                    }
                                                    ui.label(egui::RichText::new(format_size(file.size)).color(egui::Color32::from_rgb(108, 117, 125)));
                                                });
                                            });
                                        });

                                        ui.label(egui::RichText::new(&file.path).size(11.0).color(egui::Color32::from_rgb(108, 117, 125)));
                                        
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new(&file.modified).size(12.0).color(egui::Color32::from_rgb(108, 117, 125)));
                                            ui.add_space(10.0);
                                            ui.label(egui::RichText::new(&file.extension).size(11.0).color(egui::Color32::from_rgb(73, 80, 87)));
                                            ui.add_space(10.0);
                                            ui.label(egui::RichText::new(file.algo.name()).color(egui::Color32::from_rgb(0, 120, 215)).size(11.0).strong());
                                        });

                                        if let Some(hash) = &file.hash {
                                            ui.add_space(4.0);
                                            ui.horizontal(|ui| {
                                                ui.add(egui::Label::new(
                                                    egui::RichText::new(format!("哈希: {}", hash))
                                                        .monospace()
                                                        .size(11.0)
                                                        .color(egui::Color32::from_rgb(0, 120, 215))
                                                ));
                                            });
                                        } else if let Some(error) = &file.error {
                                            ui.colored_label(egui::Color32::RED, format!("❌ 错误: {}", error));
                                        } else if file.progress > 0.0 && file.progress < 1.0 {
                                            ui.horizontal(|ui| {
                                                ui.add(egui::Spinner::new().size(12.0));
                                                ui.label(egui::RichText::new(format!("正在使用 {} 计算...", file.algo.name())).italics().size(12.0).color(egui::Color32::from_rgb(0, 120, 215)));
                                                ui.add(egui::ProgressBar::new(file.progress).desired_width(100.0).show_percentage());
                                            });
                                        } else {
                                            ui.label(egui::RichText::new(format!("等待计算 ({})", file.algo.name())).italics().size(12.0).color(egui::Color32::GRAY));
                                        }
                                    });
                                });
                            }).response.interact(egui::Sense::click());

                            if response.clicked() {
                                self.selected_index = Some(original_index);
                                self.verify_result = None;
                                if let Some(hash) = &file.hash {
                                    self.trigger_copy(ui, hash.clone(), "哈希值");
                                }
                            }
                            
                            ui.add_space(8.0);
                        }
                    });

                ui.add_space(10.0);

                // 4. 进度和状态
                let active_count = self.active_tasks.load(Ordering::SeqCst);
                if active_count > 0 {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(16.0));
                        ui.label(egui::RichText::new(format!("正在并发处理 {} 个文件...", active_count)).color(egui::Color32::from_rgb(0, 120, 215)));
                    });
                    ui.add_space(5.0);
                }

                // 5. 校验与日志区
                ui.separator();
                
                ui.horizontal_top(|ui| {
                    let total_width = ui.available_width();
                    let spacing = 24.0;
                    
                    if is_mobile {
                        // 移动端/窄窗口模式：垂直堆叠
                        ui.vertical(|ui| {
                            // 比对区
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new("官方校验比对").strong());
                                ui.add_space(8.0);
                                
                                ui.horizontal(|ui| {
                                    let edit_width = ui.available_width() - 70.0;
                                    let edit_response = ui.add(egui::TextEdit::singleline(&mut self.expected_input)
                                        .hint_text("在此粘贴官方校验值...")
                                        .desired_width(edit_width));
                                    
                                    if edit_response.changed() {
                                        self.verify_result = None;
                                    }

                                    let btn = egui::Button::new(egui::RichText::new("比对").strong())
                                        .min_size(egui::vec2(60.0, 24.0));
                                    if ui.add(btn).clicked() {
                                        if let Some(selected) = self.selected_index {
                                            let mut status = 0; // 0: ok, 1: pending, 2: error
                                            let mut hash_val = None;
                                            
                                            if let Ok(files) = self.files.lock() {
                                                if let Some(file) = files.get(selected) {
                                                    if let Some(hash) = &file.hash {
                                                        hash_val = Some(hash.clone());
                                                    } else {
                                                        status = 1;
                                                    }
                                                }
                                            }

                                            match status {
                                                0 => {
                                                    if let Some(hash) = hash_val {
                                                        let expected_clean = self.expected_input.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase();
                                                        if !expected_clean.is_empty() {
                                                            self.verify_result = Some(expected_clean == hash.to_lowercase());
                                                        }
                                                    }
                                                }
                                                1 => self.show_toast("请先等待该文件计算完成"),
                                                _ => {}
                                            }
                                        } else {
                                            self.show_toast("请先在上方列表中选择一个文件");
                                        }
                                    }
                                });

                                ui.add_space(12.0);

                                if let Some(selected) = self.selected_index {
                                    if let Ok(files) = self.files.lock() {
                                        if let Some(file) = files.get(selected) {
                                            if let Some(r) = self.verify_result {
                                                let (text, color) = if r { 
                                                    ("校验结果: 一致 ✔", egui::Color32::from_rgb(0, 150, 0)) 
                                                } else { 
                                                    ("校验结果: 不一致 ✘", egui::Color32::from_rgb(220, 53, 69)) 
                                                };
                                                ui.label(egui::RichText::new(text).size(14.0).color(color).strong());
                                            } else if file.hash.is_none() {
                                                ui.label(egui::RichText::new("正在等待计算...").size(14.0).color(egui::Color32::from_rgb(108, 117, 125)).italics());
                                            } else {
                                                ui.label(egui::RichText::new("请输入校验值并点击比对").size(14.0).color(egui::Color32::from_rgb(51, 51, 51)));
                                            }
                                        }
                                    }
                                } else {
                                    ui.label(egui::RichText::new("请在上方选择一个文件进行比对").size(14.0).color(egui::Color32::from_rgb(51, 51, 51)));
                                }
                            });

                            ui.add_space(spacing);
                            ui.separator();
                            ui.add_space(spacing);

                            // 日志输出
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("结果日志").strong());
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.button("导出为 CSV").clicked() {
                                            if let Some(path) = rfd::FileDialog::new()
                                                .add_filter("CSV", &["csv"])
                                                .set_file_name("hash_results.csv")
                                                .save_file() 
                                            {
                                                let mut content = String::from("文件名,算法,哈希值,大小,修改时间\n");
                                                if let Ok(files) = self.files.lock() {
                                                    for file in files.iter() {
                                                        if let Some(hash) = &file.hash {
                                                            content.push_str(&format!("{},{},{},{},{}\n", 
                                                                file.name, file.algo.name(), hash, format_size(file.size), file.modified));
                                                        }
                                                    }
                                                }
                                                if let Err(e) = std::fs::write(path, content) {
                                                    self.show_toast(format!("导出失败: {}", e));
                                                } else {
                                                    self.show_toast("导出成功");
                                                }
                                            }
                                        }
                                        ui.add_space(8.0);
                                        if ui.button("复制全部").clicked() {
                                            let mut all_results = String::new();
                                            if let Ok(files) = self.files.lock() {
                                                for file in files.iter() {
                                                    if let Some(hash) = &file.hash {
                                                        all_results.push_str(&format!("{} [{}] => {}\n", file.name, file.algo.name(), hash));
                                                    }
                                                }
                                            }
                                            if !all_results.is_empty() {
                                                ui.output_mut(|o| o.copied_text = all_results);
                                                self.show_toast("已复制所有计算结果");
                                            }
                                        }
                                    });
                                });
                                
                                ui.add_space(8.0);
                                
                                let mut log_text = String::new();
                                if let Ok(files) = self.files.lock() {
                                     for file in files.iter() {
                                         if let Some(hash) = &file.hash {
                                             log_text.push_str(&format!("{} [{}] => {}\n", file.name, file.algo.name(), hash));
                                         } else if let Some(err) = &file.error {
                                             log_text.push_str(&format!("{} [{}] => 错误: {}\n", file.name, file.algo.name(), err));
                                         }
                                     }
                                 }

                                egui::Frame::none()
                                    .fill(egui::Color32::from_rgb(248, 249, 250))
                                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(222, 226, 230)))
                                    .rounding(8.0)
                                    .inner_margin(8.0)
                                    .show(ui, |ui| {
                                        egui::ScrollArea::vertical()
                                            .id_source("log_scroll")
                                            .max_height(120.0)
                                            .auto_shrink([false, false])
                                            .show(ui, |ui| {
                                                ui.add(egui::TextEdit::multiline(&mut log_text)
                                                    .font(egui::TextStyle::Monospace)
                                                    .desired_width(f32::INFINITY)
                                                    .desired_rows(6)
                                                    .frame(false)
                                                    .interactive(true));
                                            });
                                    });
                            });
                        });
                    } else {
                        // 宽屏模式：左右分列
                        let column_width = (total_width - spacing) / 2.0;

                        // 左侧：比对区
                        ui.allocate_ui(egui::vec2(column_width, ui.available_height()), |ui| {
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new("官方校验比对").strong());
                                ui.add_space(8.0);
                                
                                ui.horizontal(|ui| {
                                    let edit_width = ui.available_width() - 70.0;
                                    let edit_response = ui.add(egui::TextEdit::singleline(&mut self.expected_input)
                                        .hint_text("在此粘贴官方校验值...")
                                        .desired_width(edit_width));
                                    
                                    if edit_response.changed() {
                                        self.verify_result = None;
                                    }

                                    let btn = egui::Button::new(egui::RichText::new("比对").strong())
                                        .min_size(egui::vec2(60.0, 24.0));
                                    if ui.add(btn).clicked() {
                                        if let Some(selected) = self.selected_index {
                                            let mut status = 0; // 0: ok, 1: pending, 2: error
                                            let mut hash_val = None;
                                            
                                            if let Ok(files) = self.files.lock() {
                                                if let Some(file) = files.get(selected) {
                                                    if let Some(hash) = &file.hash {
                                                        hash_val = Some(hash.clone());
                                                    } else {
                                                        status = 1;
                                                    }
                                                }
                                            }

                                            match status {
                                                0 => {
                                                    if let Some(hash) = hash_val {
                                                        let expected_clean = self.expected_input.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase();
                                                        if !expected_clean.is_empty() {
                                                            self.verify_result = Some(expected_clean == hash.to_lowercase());
                                                        }
                                                    }
                                                }
                                                1 => self.show_toast("请先等待该文件计算完成"),
                                                _ => {}
                                            }
                                        } else {
                                            self.show_toast("请先在上方列表中选择一个文件");
                                        }
                                    }
                                });

                                ui.add_space(12.0);

                                if let Some(selected) = self.selected_index {
                                    if let Ok(files) = self.files.lock() {
                                        if let Some(file) = files.get(selected) {
                                            if let Some(r) = self.verify_result {
                                                let (text, color) = if r { 
                                                    ("校验结果: 一致 ✔", egui::Color32::from_rgb(0, 150, 0)) 
                                                } else { 
                                                    ("校验结果: 不一致 ✘", egui::Color32::from_rgb(220, 53, 69)) 
                                                };
                                                ui.label(egui::RichText::new(text).size(14.0).color(color).strong());
                                            } else if file.hash.is_none() {
                                                ui.label(egui::RichText::new("正在等待计算...").size(14.0).color(egui::Color32::from_rgb(108, 117, 125)).italics());
                                            } else {
                                                ui.label(egui::RichText::new("请输入校验值并点击比对").size(14.0).color(egui::Color32::from_rgb(51, 51, 51)));
                                            }
                                        }
                                    }
                                } else {
                                    ui.label(egui::RichText::new("请在上方选择一个文件进行比对").size(14.0).color(egui::Color32::from_rgb(51, 51, 51)));
                                }
                            });
                        });

                        ui.add_space(spacing);

                        // 右侧：日志输出
                        ui.allocate_ui(egui::vec2(ui.available_width(), ui.available_height()), |ui| {
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("结果日志").strong());
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.button("导出为 CSV").clicked() {
                                            if let Some(path) = rfd::FileDialog::new()
                                                .add_filter("CSV", &["csv"])
                                                .set_file_name("hash_results.csv")
                                                .save_file() 
                                            {
                                                let mut content = String::from("文件名,算法,哈希值,大小,修改时间\n");
                                                if let Ok(files) = self.files.lock() {
                                                    for file in files.iter() {
                                                        if let Some(hash) = &file.hash {
                                                            content.push_str(&format!("{},{},{},{},{}\n", 
                                                                file.name, file.algo.name(), hash, format_size(file.size), file.modified));
                                                        }
                                                    }
                                                }
                                                if let Err(e) = std::fs::write(path, content) {
                                                    self.show_toast(format!("导出失败: {}", e));
                                                } else {
                                                    self.show_toast("导出成功");
                                                }
                                            }
                                        }
                                        ui.add_space(8.0);
                                        if ui.button("复制全部结果").clicked() {
                                            let mut all_results = String::new();
                                            if let Ok(files) = self.files.lock() {
                                                for file in files.iter() {
                                                    if let Some(hash) = &file.hash {
                                                        all_results.push_str(&format!("{} [{}] => {}\n", file.name, file.algo.name(), hash));
                                                    }
                                                }
                                            }
                                            if !all_results.is_empty() {
                                                ui.output_mut(|o| o.copied_text = all_results);
                                                self.show_toast("已复制所有计算结果");
                                            }
                                        }
                                    });
                                });
                                
                                ui.add_space(8.0);
                                
                                let mut log_text = String::new();
                                if let Ok(files) = self.files.lock() {
                                     for file in files.iter() {
                                         if let Some(hash) = &file.hash {
                                             log_text.push_str(&format!("{} [{}] => {}\n", file.name, file.algo.name(), hash));
                                         } else if let Some(err) = &file.error {
                                             log_text.push_str(&format!("{} [{}] => 错误: {}\n", file.name, file.algo.name(), err));
                                         }
                                     }
                                 }

                                egui::Frame::none()
                                    .fill(egui::Color32::from_rgb(248, 249, 250))
                                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(222, 226, 230)))
                                    .rounding(8.0)
                                    .inner_margin(8.0)
                                    .show(ui, |ui| {
                                        egui::ScrollArea::vertical()
                                            .id_source("log_scroll")
                                            .max_height(120.0)
                                            .auto_shrink([false, false])
                                            .show(ui, |ui| {
                                                ui.add(egui::TextEdit::multiline(&mut log_text)
                                                    .font(egui::TextStyle::Monospace)
                                                    .desired_width(f32::INFINITY)
                                                    .desired_rows(6)
                                                    .frame(false)
                                                    .interactive(true));
                                            });
                                    });
                            });
                        });
                    }
                });
            });
        });

        if self.show_about {
            egui::Window::new("关于软件")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading(env!("CARGO_PKG_NAME"));
                        ui.label(format!("版本: {}", env!("CARGO_PKG_VERSION")));
                        ui.add_space(10.0);
                        ui.label("一个专业、高效、现代化的文件校验工具");
                        ui.label("支持 MD5, CRC32, CRC64, xxHash64, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s");
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("开发者: Yssssssss").strong());
                        ui.add_space(20.0);
                        if ui.button(" 确定 ").clicked() {
                            self.show_about = false;
                        }
                    });
                });
        }

        // 渲染 Toast 提示
        if let (Some(text), Some(start_time)) = (&self.toast_text, self.toast_start_time) {
            let elapsed = start_time.elapsed().as_secs_f32();
            let duration = 3.0;
            let fade_duration = 0.3;

            if elapsed < duration {
                let opacity = if elapsed < fade_duration {
                    elapsed / fade_duration
                } else if elapsed > duration - fade_duration {
                    (duration - elapsed) / fade_duration
                } else {
                    1.0
                };

                egui::Area::new(egui::Id::new("toast"))
                    .anchor(egui::Align2::CENTER_BOTTOM, egui::vec2(0.0, -40.0))
                    .order(egui::Order::Foreground)
                    .interactable(false)
                    .show(ctx, |ui| {
                        let frame = egui::Frame::none()
                            .fill(egui::Color32::from_black_alpha((180.0 * opacity) as u8))
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(20.0, 10.0));

                        frame.show(ui, |ui| {
                            ui.label(egui::RichText::new(text)
                                .color(egui::Color32::from_white_alpha((255.0 * opacity) as u8))
                                .size(14.0)
                                .strong());
                        });
                    });
                ctx.request_repaint();
            } else {
                self.toast_text = None;
                self.toast_start_time = None;
            }
        }

        // 拖放视觉反馈
        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            egui::Area::new(egui::Id::new("drop_overlay"))
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .order(egui::Order::Foreground)
                .interactable(false)
                .show(ctx, |ui| {
                    let screen_rect = ui.ctx().screen_rect();
                    ui.painter().rect_filled(
                        screen_rect,
                        0.0,
                        egui::Color32::from_black_alpha(150),
                    );
                    ui.painter().rect_stroke(
                        screen_rect.shrink(20.0),
                        10.0,
                        egui::Stroke::new(2.0, egui::Color32::from_rgb(0, 120, 215)),
                    );
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            egui::RichText::new("释放文件以导入")
                                .color(egui::Color32::WHITE)
                                .size(30.0)
                                .strong(),
                        );
                    });
                });
        }
    }
}

fn main() -> eframe::Result<()> {
    let icon = image::load_from_memory(ICON_DATA)
        .expect("Failed to load icon")
        .to_rgba8();
    let (width, height) = icon.dimensions();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_icon(egui::IconData {
                rgba: icon.into_raw(),
                width,
                height,
            })
            .with_inner_size([1180.0, 870.0])
            .with_min_inner_size([1180.0, 870.0]),
        ..Default::default()
    };

    eframe::run_native(
        "HM-HashChecker",
        options,
        Box::new(|cc| {
            setup_custom_fonts(&cc.egui_ctx);
            
            let mut app: HashApp = cc.storage
                .and_then(|s| eframe::get_value(s, eframe::APP_KEY))
                .unwrap_or_default();
            
            // 重新初始化无法序列化的字段
            app.active_tasks = Arc::new(AtomicUsize::new(0));
            app.files = Arc::new(Mutex::new(Vec::new()));
            app.selected_index = None;
            app.expected_input = String::new();
            app.verify_result = None;
            app.show_about = false;
            app.toast_text = None;
            app.toast_start_time = None;

            Ok::<Box<dyn eframe::App>, Box<dyn std::error::Error + Send + Sync>>(Box::new(app))
        }),
    )
}

fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    fonts.font_data.insert(
        "zh_font".to_owned(),
        egui::FontData::from_static(ZH_FONT_DATA),
    );

    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "zh_font".to_owned());

    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "zh_font".to_owned());

    ctx.set_fonts(fonts);

    let mut style = (*ctx.style()).clone();

    // 现代化的间距和圆角
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.window_margin = egui::Margin::same(20.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.visuals.window_rounding = 8.0.into();
    style.visuals.widgets.noninteractive.rounding = 4.0.into();
    style.visuals.widgets.inactive.rounding = 4.0.into();
    style.visuals.widgets.hovered.rounding = 4.0.into();
    style.visuals.widgets.active.rounding = 4.0.into();
    style.visuals.widgets.open.rounding = 4.0.into();

    // 专业配色方案 (深色/浅色自适应)
    style.visuals.extreme_bg_color = egui::Color32::from_gray(245); // 输入框等背景
    style.visuals.window_fill = egui::Color32::from_gray(255);
    style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(230, 240, 255);
    style.visuals.selection.bg_fill = egui::Color32::from_rgb(0, 120, 215);

    if let Some(text_style) = style.text_styles.get_mut(&egui::TextStyle::Heading) {
        text_style.size = 22.0;
    }
    if let Some(text_style) = style.text_styles.get_mut(&egui::TextStyle::Body) {
        text_style.size = 14.0;
    }
    if let Some(text_style) = style.text_styles.get_mut(&egui::TextStyle::Button) {
        text_style.size = 14.0;
    }
    if let Some(text_style) = style.text_styles.get_mut(&egui::TextStyle::Monospace) {
        text_style.size = 13.0;
    }

    ctx.set_style(style);
}