mod widgets;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::*,
};
use std::io;
use std::time::Duration;

use crate::scanner::{Finding, Severity};

struct App {
    findings: Vec<Finding>,
    selected: usize,
    show_detail: bool,
    should_quit: bool,
    scan_duration: Duration,
}

impl App {
    fn new(findings: Vec<Finding>, scan_duration: Duration) -> Self {
        Self {
            findings,
            selected: 0,
            show_detail: false,
            should_quit: false,
            scan_duration,
        }
    }

    fn next(&mut self) {
        if !self.findings.is_empty() {
            self.selected = (self.selected + 1) % self.findings.len();
        }
    }

    fn previous(&mut self) {
        if !self.findings.is_empty() {
            self.selected = self.selected.checked_sub(1).unwrap_or(self.findings.len() - 1);
        }
    }
}

pub fn run_tui(findings: Vec<Finding>, scan_duration: Duration) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(findings, scan_duration);

    loop {
        terminal.draw(|f| draw_ui(f, &app))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                    KeyCode::Up | KeyCode::Char('k') => app.previous(),
                    KeyCode::Enter | KeyCode::Char(' ') => app.show_detail = !app.show_detail,
                    KeyCode::Home | KeyCode::Char('g') => app.selected = 0,
                    KeyCode::End | KeyCode::Char('G') => {
                        if !app.findings.is_empty() {
                            app.selected = app.findings.len() - 1;
                        }
                    }
                    _ => {}
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

fn draw_ui(frame: &mut Frame, app: &App) {
    let area = frame.area();

    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(2),
        ])
        .split(area);

    draw_header(frame, main_layout[0]);
    draw_summary(frame, main_layout[1], app);

    if app.show_detail && !app.findings.is_empty() {
        let detail_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(main_layout[2]);
        draw_findings_list(frame, detail_layout[0], app);
        draw_finding_detail(frame, detail_layout[1], app);
    } else {
        draw_findings_list(frame, main_layout[2], app);
    }

    draw_footer(frame, main_layout[3]);
}

fn draw_header(frame: &mut Frame, area: Rect) {
    let title = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(" Guardia ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled("AI-Enhanced Code Security Scanner", Style::default().fg(Color::White)),
            Span::styled(format!(" v{}", env!("CARGO_PKG_VERSION")), Style::default().fg(Color::DarkGray)),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
    frame.render_widget(title, area);
}

fn draw_summary(frame: &mut Frame, area: Rect, app: &App) {
    let critical = app.findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = app.findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = app.findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = app.findings.iter().filter(|f| f.severity == Severity::Low).count();

    let summary = Line::from(vec![
        Span::styled(format!(" {} findings ", app.findings.len()), Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("│ "),
        Span::styled(format!("● {} critical ", critical), Style::default().fg(Color::Red)),
        Span::styled(format!("● {} high ", high), Style::default().fg(Color::Yellow)),
        Span::styled(format!("● {} medium ", medium), Style::default().fg(Color::Blue)),
        Span::styled(format!("● {} low ", low), Style::default().fg(Color::DarkGray)),
        Span::raw("│ "),
        Span::styled(format!("scanned in {:.2}s", app.scan_duration.as_secs_f64()), Style::default().fg(Color::Green)),
    ]);

    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray));
    let paragraph = Paragraph::new(summary).block(block);
    frame.render_widget(paragraph, area);
}

fn draw_findings_list(frame: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let severity_style = match f.severity {
                Severity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                Severity::High => Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                Severity::Medium => Style::default().fg(Color::Blue),
                Severity::Low => Style::default().fg(Color::DarkGray),
            };

            let line = Line::from(vec![
                Span::styled(format!(" {:>2}. ", i + 1), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{:<8} ", f.severity.to_string()), severity_style),
                Span::styled(&f.title, Style::default().fg(Color::White)),
                Span::styled(format!("  {}", f.rule_id), Style::default().fg(Color::DarkGray)),
            ]);

            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Findings ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    let mut state = ListState::default();
    state.select(Some(app.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_finding_detail(frame: &mut Frame, area: Rect, app: &App) {
    if let Some(finding) = app.findings.get(app.selected) {
        let severity_color = match finding.severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::Yellow,
            Severity::Medium => Color::Blue,
            Severity::Low => Color::DarkGray,
        };

        let detail = vec![
            Line::from(vec![
                Span::styled("Severity: ", Style::default().fg(Color::DarkGray)),
                Span::styled(finding.severity.to_string(), Style::default().fg(severity_color).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("File: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{}:{}", finding.file_path.display(), finding.line_number),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::UNDERLINED),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Description: ", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(Span::styled(&finding.description, Style::default().fg(Color::White))),
            Line::from(""),
            Line::from(vec![
                Span::styled("Code: ", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(Span::styled(
                format!("  {} │ {}", finding.line_number, &finding.line_content),
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("Fix: ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(Span::styled(&finding.suggestion, Style::default().fg(Color::Green))),
        ];

        let block = Block::default()
            .title(format!(" {} [{}] ", finding.title, finding.rule_id))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(severity_color));

        let paragraph = Paragraph::new(detail).block(block).wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }
}

fn draw_footer(frame: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" ↑↓/jk ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("navigate  "),
        Span::styled(" Enter ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("toggle detail  "),
        Span::styled(" g/G ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("top/bottom  "),
        Span::styled(" q ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("quit"),
    ]));
    frame.render_widget(footer, area);
}
