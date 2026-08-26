//! Server-rendered HTML helpers: one layout, one escaper, zero client-side
//! dependencies (no JS, no fonts, no CDN). Everything user-derived passes
//! through [`esc`].

/// HTML-escapes text content and attribute values.
#[must_use]
pub fn esc(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Page chrome: nav bar, inline stylesheet, flash banner.
///
/// `flash_ok` / `flash_err` come from the `msg` / `err` query params.
#[must_use]
pub fn layout(
    title: &str,
    setup_pending: usize,
    halted: Option<&str>,
    flash_ok: Option<&str>,
    flash_err: Option<&str>,
    body: &str,
) -> String {
    let mut page = String::with_capacity(4096 + body.len());
    page.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    page.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    page.push_str("<title>Chaperone \u{2014} ");
    page.push_str(&esc(title));
    page.push_str("</title><style>");
    page.push_str(
        "body{font-family:system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1a1d21}\
         header{background:#101418;color:#fff;padding:.8rem 1.2rem;display:flex;gap:1.2rem;align-items:center}\
         header a{color:#9fd0ff;text-decoration:none;font-weight:600}\
         main{max-width:56rem;margin:1.2rem auto;padding:0 1rem}\
         h1{font-size:1.3rem} h2{font-size:1.05rem;margin-top:1.6rem}\
         table{border-collapse:collapse;width:100%;background:#fff}\
         th,td{border:1px solid #d8dde3;padding:.45rem .6rem;text-align:left;font-size:.92rem}\
         th{background:#eef1f4}\
         input,select,textarea{font:inherit;padding:.35rem;border:1px solid #b8c0c8;border-radius:4px;width:100%;box-sizing:border-box}\
         form.inline{display:inline}\
         .card{background:#fff;border:1px solid #d8dde3;border-radius:6px;padding:1rem 1.2rem;margin-bottom:1rem}\
         .ok{background:#e5f6ec;border:1px solid #9adbb4;padding:.55rem .8rem;border-radius:6px;margin:.6rem 0}\
         .err{background:#fdeceb;border:1px solid #f2a69d;padding:.55rem .8rem;border-radius:6px;margin:.6rem 0}\
         .halt{background:#2b0b0b;color:#ffd9d4;border:1px solid #a33;padding:.7rem .9rem;border-radius:6px;margin:.6rem 0;font-weight:600}\
         .badge{font-size:.8rem;padding:.15rem .5rem;border-radius:10px;border:1px solid #b8c0c8;background:#eef1f4}\
         .allow{background:#e5f6ec}.deny{background:#fdeceb}.confirm{background:#fdf6e3}\
         .muted{color:#66707a;font-size:.85rem}\
         button{font:inherit;padding:.4rem .9rem;border-radius:4px;border:1px solid #2b62a8;background:#2b62a8;color:#fff;cursor:pointer}\
         button.danger{background:#a83232;border-color:#a83232}\
         .grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:1rem}\
         code{background:#eef1f4;padding:.05rem .3rem;border-radius:3px}",
    );
    page.push_str("</style></head><body>");

    page.push_str("<header><strong style=\"letter-spacing:.06em\">CHAPERONE</strong>");
    for (href, label) in [
        ("/", "Status"),
        ("/rules", "Rules"),
        ("/secrets", "Secrets"),
        ("/agents", "Agents"),
        ("/setup", "Setup"),
    ] {
        page.push_str(&format!("<a href=\"{href}\">{label}</a>"));
    }
    if setup_pending > 0 {
        page.push_str(&format!(
            "<span class=\"badge\" style=\"margin-left:auto;border-color:#e6b35a;background:#3a2f14;color:#ffdf9e\">\
             {setup_pending} setup step{} pending</span>",
            if setup_pending == 1 { "" } else { "s" }
        ));
    }
    page.push_str("</header><main>");

    if let Some(reason) = halted {
        page.push_str(&format!(
            "<div class=\"halt\">Gateway halted \u{2014} brokering stopped. {} \
             Restart <code>chaperone serve</code> to resume.</div>",
            esc(reason)
        ));
    }
    if let Some(m) = flash_ok {
        page.push_str(&format!("<div class=\"ok\">{}</div>", esc(m)));
    }
    if let Some(m) = flash_err {
        page.push_str(&format!("<div class=\"err\">{}</div>", esc(m)));
    }

    page.push_str(body);
    page.push_str("</main></body></html>");
    page
}

/// A labeled form field row.
#[must_use]
pub fn field(label: &str, input: &str) -> String {
    format!(
        "<p><label><strong>{}</strong><br>{input}</label></p>",
        esc(label)
    )
}

/// Effect badge cell.
#[must_use]
pub fn effect_badge(effect: &str) -> String {
    let class = match effect {
        "allow" => "allow",
        "deny" => "deny",
        _ => "confirm",
    };
    format!("<span class=\"badge {class}\">{}</span>", esc(effect))
}
