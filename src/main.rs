#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod patcher;

use eframe::egui;
use patcher::{PatchOptions, PatchReport, PatchType};
use std::path::PathBuf;
use std::time::Instant;

// ── CODEX-style dark palette ───────────────────────────────────────────────

const COL_BG: egui::Color32 = egui::Color32::from_rgb(15, 15, 18);
const COL_BG_PANEL: egui::Color32 = egui::Color32::from_rgba_premultiplied(22, 22, 28, 230);
const COL_BG_INPUT: egui::Color32 = egui::Color32::from_rgb(10, 10, 14);
const COL_BG_CONSOLE: egui::Color32 = egui::Color32::from_rgba_premultiplied(5, 5, 8, 200);
const COL_BORDER: egui::Color32 = egui::Color32::from_rgb(55, 55, 65);
const COL_BORDER_BRIGHT: egui::Color32 = egui::Color32::from_rgb(80, 80, 95);
const COL_TEXT: egui::Color32 = egui::Color32::from_rgb(200, 200, 210);
const COL_TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(120, 120, 135);
const COL_TEXT_BRIGHT: egui::Color32 = egui::Color32::from_rgb(230, 230, 240);
const COL_ACCENT: egui::Color32 = egui::Color32::from_rgb(180, 140, 60);
const COL_ACCENT_BRIGHT: egui::Color32 = egui::Color32::from_rgb(220, 180, 80);
#[allow(dead_code)]
const COL_RED: egui::Color32 = egui::Color32::from_rgb(190, 50, 30);
const COL_RED_BRIGHT: egui::Color32 = egui::Color32::from_rgb(220, 70, 40);
const COL_GREEN: egui::Color32 = egui::Color32::from_rgb(60, 180, 80);
const COL_ORANGE: egui::Color32 = egui::Color32::from_rgb(210, 130, 40);
const COL_CYAN: egui::Color32 = egui::Color32::from_rgb(80, 170, 210);
const COL_BTN_BG: egui::Color32 = egui::Color32::from_rgb(35, 35, 42);
const COL_BTN_HOVER: egui::Color32 = egui::Color32::from_rgb(50, 50, 60);
const COL_PROGRESS_BG: egui::Color32 = egui::Color32::from_rgb(30, 30, 36);
const COL_PROGRESS_FG: egui::Color32 = egui::Color32::from_rgb(185, 60, 30);
const COL_CHECK_ON: egui::Color32 = egui::Color32::from_rgb(200, 200, 210);
const COL_CHECK_OFF: egui::Color32 = egui::Color32::from_rgb(70, 70, 80);


// ── App State ──────────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum AppState {
    Idle,
    FileLoaded,
    Done,
}

struct CrackerApp {
    state: AppState,
    firmware_path: Option<PathBuf>,
    firmware_data: Option<Vec<u8>>,
    firmware_info: Vec<String>,
    path_display: String,

    opt_timer: bool,
    opt_branch: bool,
    opt_keygen: bool,
    opt_key_bypass: bool,

    patched_data: Option<Vec<u8>>,
    report: Option<PatchReport>,
    progress: f32, // 0.0 to 1.0

    start_time: Instant,
    log_lines: Vec<(String, egui::Color32)>,
    bg_texture: Option<egui::TextureHandle>,
}

impl Default for CrackerApp {
    fn default() -> Self {
        Self {
            state: AppState::Idle,
            firmware_path: None,
            firmware_data: None,
            firmware_info: Vec::new(),
            path_display: String::new(),
            opt_timer: true,
            opt_branch: true,
            opt_keygen: true,
            opt_key_bypass: true,
            patched_data: None,
            report: None,
            progress: 0.0,
            start_time: Instant::now(),
            log_lines: vec![
                ("PIN2DMD Firmware Cracker initialized".into(), COL_TEXT_DIM),
                ("Waiting for firmware file...".into(), COL_TEXT_DIM),
            ],
            bg_texture: None,
        }
    }
}

impl CrackerApp {
    fn log(&mut self, msg: &str, color: egui::Color32) {
        self.log_lines.push((msg.to_string(), color));
    }

    fn load_firmware(&mut self, path: PathBuf) {
        match std::fs::read(&path) {
            Ok(data) => {
                let info = patcher::analyze_firmware(&data);
                self.log(
                    &format!("Loaded: {}", path.display()),
                    COL_GREEN,
                );
                for line in &info {
                    self.log(line, COL_TEXT_DIM);
                }
                self.firmware_info = info;
                self.path_display = path.to_string_lossy().to_string();
                self.firmware_data = Some(data);
                self.firmware_path = Some(path);
                self.state = AppState::FileLoaded;
                self.patched_data = None;
                self.report = None;
                self.progress = 0.0;
            }
            Err(e) => {
                self.log(&format!("ERROR: {}", e), COL_RED_BRIGHT);
            }
        }
    }

    fn run_patch(&mut self) {
        let Some(original) = self.firmware_data.clone() else {
            return;
        };

        self.log("────────────────────────────────────────", COL_BORDER);
        self.log("Cracking firmware protections...", COL_ACCENT_BRIGHT);

        let options = PatchOptions {
            timer: self.opt_timer,
            branch: self.opt_branch,
            keygen: self.opt_keygen,
            key_bypass: self.opt_key_bypass,
        };

        let (patched, report) = patcher::apply_patches(&original, options);

        for p in &report.patches {
            let color = match p.patch_type {
                PatchType::Timer => COL_ORANGE,
                PatchType::Branch => COL_CYAN,
                PatchType::Keygen => COL_GREEN,
                PatchType::KeyBypass => COL_ACCENT,
            };
            self.log(&p.description, color);
        }

        for err in &report.errors {
            self.log(&format!("WARNING: {}", err), COL_RED_BRIGHT);
        }

        let total = report.total_patches();
        if report.errors.is_empty() {
            self.log(
                &format!("{} patches applied - ALL PROTECTIONS DEFEATED", total),
                COL_GREEN,
            );
        } else {
            self.log(
                &format!("{} patches applied (with warnings)", total),
                COL_ORANGE,
            );
        }

        self.progress = 1.0;
        self.patched_data = Some(patched);
        self.report = Some(report);
        self.state = AppState::Done;
    }

    fn save_firmware(&mut self) {
        let Some(ref data) = self.patched_data else {
            return;
        };

        let default_name = self
            .firmware_path
            .as_ref()
            .and_then(|p| p.file_stem())
            .map(|s| format!("{}_cracked.bin", s.to_string_lossy()))
            .unwrap_or_else(|| "PIN2DMD_cracked.bin".into());

        let dialog = rfd::FileDialog::new()
            .set_file_name(&default_name)
            .add_filter("Binary firmware", &["bin"])
            .add_filter("All files", &["*"]);

        if let Some(path) = dialog.save_file() {
            match std::fs::write(&path, data) {
                Ok(_) => {
                    self.log(
                        &format!("Saved to: {}", path.display()),
                        COL_GREEN,
                    );
                }
                Err(e) => {
                    self.log(&format!("Save error: {}", e), COL_RED_BRIGHT);
                }
            }
        }
    }
}

// ── Helper: draw a CODEX-style grouped section ─────────────────────────────

fn section_frame(ui: &mut egui::Ui, title: &str, add_contents: impl FnOnce(&mut egui::Ui)) {
    let outer = egui::Frame::new()
        .fill(COL_BG_PANEL)
        .stroke(egui::Stroke::new(1.0, COL_BORDER))
        .corner_radius(2.0)
        .inner_margin(egui::Margin::symmetric(12, 10))
        .outer_margin(egui::Margin::symmetric(8, 4));

    outer.show(ui, |ui| {
        // Section title
        ui.label(
            egui::RichText::new(title)
                .size(12.0)
                .color(COL_TEXT_BRIGHT)
                .strong(),
        );
        ui.set_width(480.0);
        ui.add_space(6.0);
        add_contents(ui);
    });
}

fn dark_button(ui: &mut egui::Ui, text: &str, width: f32, height: Option<f32>) -> bool {
    let h = height.unwrap_or(28.0);
    let btn = egui::Button::new(
        egui::RichText::new(text).size(11.5).color(COL_TEXT),
    )
    .fill(COL_BTN_BG)
    .stroke(egui::Stroke::new(1.0, COL_BORDER))
    .corner_radius(2.0)
    .min_size(egui::vec2(width, h)); 
    ui.add(btn).clicked()
}

// ── Main UI ────────────────────────────────────────────────────────────────

impl eframe::App for CrackerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let elapsed = self.start_time.elapsed().as_secs_f32();

        // ── Global style ───────────────────────────────────────────────
        let mut style = (*ctx.style()).clone();
        style.visuals.dark_mode = true;
        style.visuals.override_text_color = Some(COL_TEXT);
        style.visuals.panel_fill = COL_BG;
        style.visuals.window_fill = COL_BG_PANEL;
        style.visuals.extreme_bg_color = COL_BG_INPUT;
        style.visuals.widgets.noninteractive.bg_fill = COL_BG_PANEL;
        style.visuals.widgets.noninteractive.bg_stroke =
            egui::Stroke::new(1.0, COL_BORDER);
        style.visuals.widgets.inactive.bg_fill = COL_BTN_BG;
        style.visuals.widgets.inactive.bg_stroke =
            egui::Stroke::new(1.0, COL_BORDER);
        style.visuals.widgets.hovered.bg_fill = COL_BTN_HOVER;
        style.visuals.widgets.hovered.bg_stroke =
            egui::Stroke::new(1.0, COL_BORDER_BRIGHT);
        style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(60, 60, 70);
        style.visuals.widgets.active.bg_stroke =
            egui::Stroke::new(1.0, COL_BORDER_BRIGHT);
        style.visuals.selection.bg_fill =
            egui::Color32::from_rgba_premultiplied(80, 80, 100, 60);
        style.visuals.selection.stroke = egui::Stroke::new(1.0, COL_BORDER_BRIGHT);
        style.spacing.item_spacing = egui::vec2(8.0, 4.0);
        ctx.set_style(style);

        ctx.request_repaint();

        // ── Load background texture (once) ────────────────────────────
        if self.bg_texture.is_none() {
            let image_data = include_bytes!("background.png");
            let img = image::load_from_memory(image_data).expect("Failed to load background.png");
            let rgba = img.to_rgba8();
            let size = [rgba.width() as usize, rgba.height() as usize];
            let color_image = egui::ColorImage::from_rgba_unmultiplied(size, rgba.as_raw());
            self.bg_texture = Some(ctx.load_texture(
                "background",
                color_image,
                egui::TextureOptions::LINEAR,
            ));
        }

        // ── Single central panel with vertical layout ──────────────────
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(egui::Color32::TRANSPARENT)
                    .inner_margin(egui::Margin::symmetric(6, 6)),
            )
            .show(ctx, |ui| {
                // Paint background image
                if let Some(tex) = &self.bg_texture {
                    let rect = ui.max_rect();
                    ui.painter().image(
                        tex.id(),
                        rect,
                        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                        egui::Color32::WHITE,
                    );
                    // Semi-transparent overlay for readability
                    ui.painter().rect_filled(
                        rect,
                        0.0,
                        egui::Color32::from_rgba_unmultiplied(15, 15, 18, 50),
                    );
                }
                // Constrain width like CODEX installer
                let max_w = 520.0;
                let avail = ui.available_width();
                let pad = ((avail - max_w) / 2.0).max(0.0);

                ui.horizontal(|ui| {
                    ui.add_space(pad);
                    ui.vertical(|ui| {
                        ui.set_max_width(max_w);

                        // ── Banner ─────────────────────────────────────
                        ui.vertical_centered(|ui| {
                            // Metallic color animation
                            let t = (elapsed * 0.4).sin() * 0.5 + 0.5;
                            let r = (200.0 + t * 80.0) as u8;
                            let g = (175.0 + t * 60.0) as u8;
                            let b = (60.0 + t * 40.0) as u8;
                            let banner_col = egui::Color32::from_rgb(r, g, b);

                            ui.label(
                                egui::RichText::new("HARLOCK")
                                    .family(egui::FontFamily::Name("SpaceAge".into()))
                                    .size(64.0)
                                    .color(banner_col),
                            );
                        });

                        ui.add_space(6.0);

                        // ── Section 1: Firmware file ───────────────────
                        section_frame(ui, "Firmware file", |ui| {
                            ui.horizontal(|ui| {
                                let field = egui::Frame::new()
                                    .fill(COL_BG_INPUT)
                                    .stroke(egui::Stroke::new(1.0, COL_BORDER))
                                    .corner_radius(1.0)
                                    .inner_margin(egui::Margin::symmetric(6, 4));

                                field.show(ui, |ui| {
                                    ui.set_width(350.0);
                                    let display = if self.path_display.is_empty() {
                                        "No file selected..."
                                    } else {
                                        &self.path_display
                                    };
                                    ui.label(
                                        egui::RichText::new(display)
                                            .monospace()
                                            .size(10.5)
                                            .color(if self.path_display.is_empty() {
                                                COL_TEXT_DIM
                                            } else {
                                                COL_TEXT
                                            }),
                                    );
                                });

                                if dark_button(ui, "Browse...", 100.0, Some(22.0)) {
                                    let dialog = rfd::FileDialog::new()
                                        .add_filter("Binary firmware", &["bin"])
                                        .add_filter("All files", &["*"]);
                                    if let Some(path) = dialog.pick_file() {
                                        self.load_firmware(path);
                                    }
                                }
                            });

                            // Firmware info line
                            if !self.firmware_info.is_empty() {
                                ui.add_space(4.0);
                                for info in &self.firmware_info {
                                    ui.label(
                                        egui::RichText::new(info)
                                            .monospace()
                                            .size(9.0)
                                            .color(COL_TEXT_DIM),
                                    );
                                }
                            }
                        });

                        ui.add_space(2.0);

                        // ── Section 2: Patches to apply ────────────────
                        section_frame(ui, "Protections to crack", |ui| {
                            let mut checkbox_row = |checked: &mut bool, label: &str, desc: &str| {
                                ui.horizontal(|ui| {
                                    // Custom styled checkbox
                                    let (rect, response) = ui.allocate_exact_size(
                                        egui::vec2(14.0, 14.0),
                                        egui::Sense::click(),
                                    );
                                    if response.clicked() {
                                        *checked = !*checked;
                                    }

                                    let painter = ui.painter();
                                    painter.rect_stroke(
                                        rect,
                                        1.0,
                                        egui::Stroke::new(1.0, COL_BORDER_BRIGHT),
                                        egui::StrokeKind::Outside,
                                    );
                                    if *checked {
                                        // Draw checkmark
                                        let c = rect.center();
                                        painter.line_segment(
                                            [
                                                egui::pos2(c.x - 3.0, c.y),
                                                egui::pos2(c.x - 1.0, c.y + 3.0),
                                            ],
                                            egui::Stroke::new(2.0, COL_CHECK_ON),
                                        );
                                        painter.line_segment(
                                            [
                                                egui::pos2(c.x - 1.0, c.y + 3.0),
                                                egui::pos2(c.x + 4.0, c.y - 2.0),
                                            ],
                                            egui::Stroke::new(2.0, COL_CHECK_ON),
                                        );
                                    }

                                    let text_col = if *checked { COL_TEXT } else { COL_CHECK_OFF };
                                    ui.label(
                                        egui::RichText::new(label)
                                            .size(11.0)
                                            .color(text_col),
                                    );
                                    ui.label(
                                        egui::RichText::new(desc)
                                            .size(9.5)
                                            .color(COL_TEXT_DIM),
                                    );
                                });
                            };

                            checkbox_row(
                                &mut self.opt_keygen,
                                "Keygen bypass",
                                "- force hw validation to 'N'",
                            );
                            checkbox_row(
                                &mut self.opt_timer,
                                "Timer extension",
                                "- 3min -> 49.7 days",
                            );
                            checkbox_row(
                                &mut self.opt_branch,
                                "Branch override",
                                "- skip millis() check",
                            );
                            checkbox_row(
                                &mut self.opt_key_bypass,
                                "Key file bypass",
                                "- NOP key validation",
                            );
                        });

                        ui.add_space(2.0);

                        // ── Section 3: Progress + Actions ──────────────
                        section_frame(ui, "Progress", |ui| {
                            // Progress bar (CODEX-style: dark bg, red/orange fill)
                            let (bar_rect, _) = ui.allocate_exact_size(
                                egui::vec2(ui.available_width(), 16.0),
                                egui::Sense::hover(),
                            );
                            let painter = ui.painter();
                            // Background
                            painter.rect_filled(bar_rect, 1.0, COL_PROGRESS_BG);
                            painter.rect_stroke(
                                bar_rect,
                                1.0,
                                egui::Stroke::new(1.0, COL_BORDER),
                                egui::StrokeKind::Outside,
                            );
                            // Fill
                            if self.progress > 0.0 {
                                let fill_w = bar_rect.width() * self.progress;
                                let fill_rect = egui::Rect::from_min_size(
                                    bar_rect.min,
                                    egui::vec2(fill_w, bar_rect.height()),
                                );
                                painter.rect_filled(fill_rect, 1.0, COL_PROGRESS_FG);

                                // Percentage text
                                let pct = format!("{}%", (self.progress * 100.0) as u32);
                                painter.text(
                                    bar_rect.center(),
                                    egui::Align2::CENTER_CENTER,
                                    pct,
                                    egui::FontId::monospace(10.0),
                                    COL_TEXT_BRIGHT,
                                );
                            }

                            ui.add_space(8.0);

                            // Summary line
                            if let Some(ref report) = self.report {
                                let summary = format!(
                                    "{} keygen | {} timer | {} branch | {} key_bypass",
                                    report.patches_by_type(PatchType::Keygen),
                                    report.patches_by_type(PatchType::Timer),
                                    report.patches_by_type(PatchType::Branch),
                                    report.patches_by_type(PatchType::KeyBypass),
                                );
                                ui.label(
                                    egui::RichText::new(summary)
                                        .monospace()
                                        .size(9.5)
                                        .color(COL_TEXT_DIM),
                                );
                                ui.add_space(4.0);
                            }

                            // Buttons row
                            ui.horizontal(|ui| {
                                let any_patch = self.opt_timer
                                    || self.opt_branch
                                    || self.opt_keygen
                                    || self.opt_key_bypass;
                                let can_crack =
                                    self.firmware_data.is_some() && any_patch;

                                // Crack button
                                let crack_label = if self.state == AppState::Done {
                                    "Crack again"
                                } else {
                                    "Crack"
                                };
                                let crack_btn = ui.add_enabled(
                                    can_crack,
                                    egui::Button::new(
                                        egui::RichText::new(crack_label)
                                            .size(12.0)
                                            .color(if can_crack {
                                                COL_TEXT_BRIGHT
                                            } else {
                                                COL_TEXT_DIM
                                            }),
                                    )
                                    .fill(if can_crack {
                                        COL_BTN_BG
                                    } else {
                                        COL_BG_INPUT
                                    })
                                    .stroke(egui::Stroke::new(1.0, COL_BORDER))
                                    .corner_radius(2.0)
                                    .min_size(egui::vec2(236.5, 30.0)),
                                );
                                if crack_btn.clicked() {
                                    self.run_patch();
                                }

                                // Save button
                                let can_save = self.patched_data.is_some();
                                let save_btn = ui.add_enabled(
                                    can_save,
                                    egui::Button::new(
                                        egui::RichText::new("Save cracked .bin")
                                            .size(12.0)
                                            .color(if can_save {
                                                COL_TEXT_BRIGHT
                                            } else {
                                                COL_TEXT_DIM
                                            }),
                                    )
                                    .fill(if can_save {
                                        COL_BTN_BG
                                    } else {
                                        COL_BG_INPUT
                                    })
                                    .stroke(egui::Stroke::new(1.0, COL_BORDER))
                                    .corner_radius(2.0)
                                    .min_size(egui::vec2(236.5, 30.0)),
                                );
                                if save_btn.clicked() {
                                    self.save_firmware();
                                }
                            });
                        });

                        ui.add_space(2.0);

                        // ── Section 4: Console log ─────────────────────
                        let remaining = ui.available_height() - 16.0;
                        let console_h = remaining.max(120.0);

                        let outer = egui::Frame::new()
                            .fill(COL_BG_CONSOLE)
                            .stroke(egui::Stroke::new(1.0, COL_BORDER))
                            .corner_radius(2.0)
                            .inner_margin(egui::Margin::symmetric(6, 4))
                            .outer_margin(egui::Margin::symmetric(8, 4));

                        outer.show(ui, |ui| {
                            ui.set_min_height(console_h);

                            egui::ScrollArea::vertical()
                                .auto_shrink([false, false])
                                .stick_to_bottom(true)
                                .max_height(console_h)
                                .show(ui, |ui| {
                                    for (line, color) in &self.log_lines {
                                        ui.label(
                                            egui::RichText::new(line)
                                                .monospace()
                                                .size(10.0)
                                                .color(*color),
                                        );
                                    }

                                    // Blinking cursor
                                    let cursor =
                                        if ((elapsed * 2.0) as u32) % 2 == 0 {
                                            ">"
                                        } else {
                                            " "
                                        };
                                    ui.label(
                                        egui::RichText::new(cursor)
                                            .monospace()
                                            .size(10.0)
                                            .color(COL_TEXT_DIM),
                                    );
                                });
                        });
                    });
                });
            });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([540.0, 574.0])
            .with_title("PIN2DMD Cracker")
            .with_resizable(false)
            .with_maximize_button(false),
        ..Default::default()
    };

    eframe::run_native(
        "PIN2DMD Cracker",
        options,
        Box::new(|cc| {
            // Load custom "Space Age" font
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                "SpaceAge".to_owned(),
                std::sync::Arc::new(egui::FontData::from_static(
                    include_bytes!("space age.ttf"),
                )),
            );
            fonts
                .families
                .entry(egui::FontFamily::Name("SpaceAge".into()))
                .or_default()
                .insert(0, "SpaceAge".to_owned());
            cc.egui_ctx.set_fonts(fonts);

            Ok(Box::new(CrackerApp::default()))
        }),
    )
}
