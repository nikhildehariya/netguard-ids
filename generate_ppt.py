import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

def create_presentation():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]  # Blank layout

    # Colors
    BG_COLOR = RGBColor(15, 23, 42)        # Slate 900 #0F172A
    CARD_BG = RGBColor(30, 41, 59)        # Slate 800 #1E293B
    BORDER_COLOR = RGBColor(51, 65, 85)   # Slate 700 #334155
    TEXT_MAIN = RGBColor(248, 250, 252)   # Slate 50 #F8FAFC
    TEXT_MUTED = RGBColor(148, 163, 184)  # Slate 400 #94A3B8
    ACCENT_BLUE = RGBColor(56, 189, 248)  # Sky 400 #38BDF8
    ACCENT_GREEN = RGBColor(74, 222, 128) # Emerald 400 #4ADE80
    ACCENT_PURPLE = RGBColor(192, 132, 252)# Purple 400 #C084FC
    ACCENT_AMBER = RGBColor(251, 191, 36) # Amber 400 #FBBF24

    def add_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_COLOR
        bg.line.fill.background()
        return bg

    def add_header(slide, title_text, category_text="NETGUARD IDS v2.2"):
        # Category Tag
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.5), Inches(11.7), Inches(0.4))
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category_text.upper()
        p_cat.font.size = Pt(11)
        p_cat.font.bold = True
        p_cat.font.color.rgb = ACCENT_BLUE
        p_cat.font.name = "Calibri"

        # Main Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.85), Inches(11.7), Inches(0.8))
        tf_title = title_box.text_frame
        tf_title.word_wrap = True
        p_title = tf_title.paragraphs[0]
        p_title.text = title_text
        p_title.font.size = Pt(26)
        p_title.font.bold = True
        p_title.font.color.rgb = TEXT_MAIN
        p_title.font.name = "Calibri"

    def create_card(slide, left, top, width, height, bg_color=CARD_BG, border_color=BORDER_COLOR):
        shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
        shape.fill.solid()
        shape.fill.fore_color.rgb = bg_color
        if border_color:
            shape.line.color.rgb = border_color
            shape.line.width = Pt(1.5)
        else:
            shape.line.fill.background()
        return shape

    # ==========================================
    # SLIDE 1: TITLE SLIDE
    # ==========================================
    slide1 = prs.slides.add_slide(blank_layout)
    add_background(slide1)

    # Decorative Card for Title
    create_card(slide1, 0.8, 0.8, 11.733, 5.9, bg_color=CARD_BG, border_color=ACCENT_BLUE)

    # Title Text Box
    t_box = slide1.shapes.add_textbox(Inches(1.2), Inches(1.2), Inches(10.9), Inches(2.2))
    tf1 = t_box.text_frame
    tf1.word_wrap = True
    
    p0 = tf1.paragraphs[0]
    p0.text = "🛡️ NETGUARD IDS v2.2"
    p0.font.size = Pt(36)
    p0.font.bold = True
    p0.font.color.rgb = ACCENT_BLUE
    p0.font.name = "Calibri"

    p1 = tf1.add_paragraph()
    p1.text = "Enterprise IoT Network Detection & Response (NDR) and Intrusion Prevention System (NIPS)"
    p1.font.size = Pt(20)
    p1.font.color.rgb = TEXT_MAIN
    p1.font.name = "Calibri"
    p1.space_before = Pt(10)

    # Info Grid Cards on Slide 1
    # Card 1: Team Member
    create_card(slide1, 1.2, 3.8, 5.2, 2.4, bg_color=BG_COLOR, border_color=BORDER_COLOR)
    tb_m = slide1.shapes.add_textbox(Inches(1.4), Inches(4.0), Inches(4.8), Inches(2.0))
    tf_m = tb_m.text_frame
    tf_m.word_wrap = True
    
    pm1 = tf_m.paragraphs[0]
    pm1.text = "👨‍💻 PROJECT PRESENTED BY"
    pm1.font.size = Pt(12)
    pm1.font.bold = True
    pm1.font.color.rgb = ACCENT_GREEN
    
    pm2 = tf_m.add_paragraph()
    pm2.text = "Nikhil Dehariya"
    pm2.font.size = Pt(22)
    pm2.font.bold = True
    pm2.font.color.rgb = TEXT_MAIN
    pm2.space_before = Pt(6)

    pm3 = tf_m.add_paragraph()
    pm3.text = "B.Tech AIDS | Department of Artificial Intelligence & Data Science\nJai Narain College of Technology (JNCT), Bhopal"
    pm3.font.size = Pt(13)
    pm3.font.color.rgb = TEXT_MUTED
    pm3.space_before = Pt(4)

    # Card 2: Project Mentor
    create_card(slide1, 6.7, 3.8, 5.4, 2.4, bg_color=BG_COLOR, border_color=BORDER_COLOR)
    tb_g = slide1.shapes.add_textbox(Inches(6.9), Inches(4.0), Inches(5.0), Inches(2.0))
    tf_g = tb_g.text_frame
    tf_g.word_wrap = True
    
    pg1 = tf_g.paragraphs[0]
    pg1.text = "🎓 GUIDED BY (MENTOR)"
    pg1.font.size = Pt(12)
    pg1.font.bold = True
    pg1.font.color.rgb = ACCENT_PURPLE
    
    pg2 = tf_g.add_paragraph()
    pg2.text = "[Mentor / Guide Name]"
    pg2.font.size = Pt(22)
    pg2.font.bold = True
    pg2.font.color.rgb = TEXT_MAIN
    pg2.space_before = Pt(6)

    pg3 = tf_g.add_paragraph()
    pg3.text = "Department of Artificial Intelligence & Data Science\nJai Narain College of Technology (JNCT), Bhopal"
    pg3.font.size = Pt(13)
    pg3.font.color.rgb = TEXT_MUTED
    pg3.space_before = Pt(4)


    # ==========================================
    # SLIDE 2: INTRODUCTION & PROBLEM STATEMENT
    # ==========================================
    slide2 = prs.slides.add_slide(blank_layout)
    add_background(slide2)
    add_header(slide2, "Introduction & Problem Statement")

    # Left Box: Problem Statement
    create_card(slide2, 0.8, 1.8, 5.6, 5.0)
    tb_s2_l = slide2.shapes.add_textbox(Inches(1.1), Inches(2.0), Inches(5.0), Inches(4.5))
    tf_s2_l = tb_s2_l.text_frame
    tf_s2_l.word_wrap = True

    p = tf_s2_l.paragraphs[0]
    p.text = "⚠️ THE CHALLENGE IN IOT SECURITY"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_AMBER

    points_l = [
        ("Explosive IoT Growth", "Billions of industrial and smart IoT devices lack standard endpoint security agents."),
        ("Legacy IDS Limitations", "Traditional signature-based systems fail against novel zero-day exploits and high-burst DDoS traffic."),
        ("Purdue Level 1-3 Risks", "Controllers, sensors, and supervisory networks are increasingly targeted by sophisticated attacks."),
        ("High False Alarm Rates", "Conventional rules trigger overwhelming false alerts without AI context or explainability.")
    ]

    for title, desc in points_l:
        p_t = tf_s2_l.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = TEXT_MAIN
        p_t.space_before = Pt(12)
        
        run = p_t.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED

    # Right Box: NetGuard Solution
    create_card(slide2, 6.8, 1.8, 5.7, 5.0)
    tb_s2_r = slide2.shapes.add_textbox(Inches(7.1), Inches(2.0), Inches(5.1), Inches(4.5))
    tf_s2_r = tb_s2_r.text_frame
    tf_s2_r.word_wrap = True

    p = tf_s2_r.paragraphs[0]
    p.text = "💡 THE NETGUARD IDS SOLUTION"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_GREEN

    points_r = [
        ("Dual-ML Intelligence", "Combines supervised XGBoost classification (90.25% F1) with Isolation Forest zero-day anomaly detection."),
        ("Sub-Second Telemetry", "Real-time packet sniffing, 1-second telemetry pulses, and instant React dashboard updates."),
        ("Automated Containment", "OS-level firewall integration (Windows Firewall & Linux iptables) automatically blocks hostiles."),
        ("Hybrid Storage Sync", "Ultra-fast 1ms local SQLite WAL coupled with non-blocking 30-second sync to Neon Cloud PostgreSQL.")
    ]

    for title, desc in points_r:
        p_t = tf_s2_r.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = TEXT_MAIN
        p_t.space_before = Pt(12)
        
        run = p_t.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED


    # ==========================================
    # SLIDE 3: KEY FEATURES & CAPABILITIES
    # ==========================================
    slide3 = prs.slides.add_slide(blank_layout)
    add_background(slide3)
    add_header(slide3, "Key Features & Core Capabilities")

    features = [
        ("🤖 Dual-ML Engine", "XGBoost classifier (CIC-IDS2018) + Isolation Forest for zero-day threat discovery.", ACCENT_BLUE),
        ("⚡ Redis Flow Buffer", "High-burst queueing for DDoS resilience with seamless fallback to direct HTTP.", ACCENT_PURPLE),
        ("🗄️ Hybrid Dual DB", "1ms local SQLite WAL mode + non-blocking background daemon sync to Neon Cloud PostgreSQL.", ACCENT_GREEN),
        ("🚫 Auto Containment", "Sub-second dynamic firewall enforcement (Windows netsh & Linux iptables) with IP whitelist safety.", ACCENT_AMBER),
        ("🔎 Network Scanner", "Instant ARP discovery & Nmap scanning for device profiling, port analysis, and gateway mapping.", ACCENT_BLUE),
        ("🤖 GenAI Copilot", "Integrated AI assistant for natural language threat querying, report generation, and SHAP XAI breakdown.", ACCENT_GREEN)
    ]

    for idx, (title, desc, color) in enumerate(features):
        row = idx // 3
        col = idx % 3
        left = 0.8 + col * 3.966
        top = 1.8 + row * 2.5

        create_card(slide3, left, top, 3.8, 2.3)
        tb = slide3.shapes.add_textbox(Inches(left + 0.2), Inches(top + 0.2), Inches(3.4), Inches(1.9))
        tf = tb.text_frame
        tf.word_wrap = True

        p1 = tf.paragraphs[0]
        p1.text = title
        p1.font.size = Pt(16)
        p1.font.bold = True
        p1.font.color.rgb = color

        p2 = tf.add_paragraph()
        p2.text = desc
        p2.font.size = Pt(12)
        p2.font.color.rgb = TEXT_MUTED
        p2.space_before = Pt(8)


    # ==========================================
    # SLIDE 4: SYSTEM ARCHITECTURE & PIPELINE
    # ==========================================
    slide4 = prs.slides.add_slide(blank_layout)
    add_background(slide4)
    add_header(slide4, "System Architecture & Data Pipeline")

    steps = [
        ("1. Packet Capture", "Scapy Engine extracts 80 flow features from active network interfaces (2s flushes).", ACCENT_BLUE),
        ("2. Buffer & Queue", "Redis Streams handle high-velocity packet spikes with automatic HTTP bypass fallback.", ACCENT_PURPLE),
        ("3. ML Inference", "XGBoost classifies attack types; Isolation Forest flags unknown zero-day anomalies.", ACCENT_AMBER),
        ("4. Dual DB & Sync", "1ms SQLite local logging + 30s background daemon sync to Neon Cloud PostgreSQL.", ACCENT_GREEN)
    ]

    for idx, (title, desc, color) in enumerate(steps):
        left = 0.8 + idx * 2.98
        create_card(slide4, left, 1.8, 2.8, 3.2)
        tb = slide4.shapes.add_textbox(Inches(left + 0.15), Inches(1.95), Inches(2.5), Inches(2.9))
        tf = tb.text_frame
        tf.word_wrap = True

        p1 = tf.paragraphs[0]
        p1.text = title
        p1.font.size = Pt(15)
        p1.font.bold = True
        p1.font.color.rgb = color

        p2 = tf.add_paragraph()
        p2.text = desc
        p2.font.size = Pt(12)
        p2.font.color.rgb = TEXT_MUTED
        p2.space_before = Pt(10)

    # Bottom Summary Bar
    create_card(slide4, 0.8, 5.2, 11.733, 1.6, bg_color=CARD_BG, border_color=ACCENT_BLUE)
    tb_b = slide4.shapes.add_textbox(Inches(1.0), Inches(5.35), Inches(11.3), Inches(1.3))
    tf_b = tb_b.text_frame
    tf_b.word_wrap = True
    
    pb1 = tf_b.paragraphs[0]
    pb1.text = "🎯 REAL-TIME MONITORING & ALERTS"
    pb1.font.size = Pt(14)
    pb1.font.bold = True
    pb1.font.color.rgb = ACCENT_BLUE

    pb2 = tf_b.add_paragraph()
    pb2.text = "FastAPI Backend (Port 8081) streams live pulse telemetry to React 19 Dashboard (Port 5174). Instant alerting triggered via HTML Email (SMTP) and Telegram Bot on critical attack events."
    pb2.font.size = Pt(13)
    pb2.font.color.rgb = TEXT_MAIN
    pb2.space_before = Pt(6)


    # ==========================================
    # SLIDE 5: ML MODELS & PERFORMANCE
    # ==========================================
    slide5 = prs.slides.add_slide(blank_layout)
    add_background(slide5)
    add_header(slide5, "Machine Learning Models & Benchmark Performance")

    # Metric Cards on Top
    metrics = [
        ("CIC-IDS2018", "Benchmark Dataset", ACCENT_BLUE),
        ("8.2 Million", "Trained Flow Samples", ACCENT_PURPLE),
        ("80 Features", "Extracted per Flow", ACCENT_AMBER),
        ("90.25%", "Overall Macro F1-Score", ACCENT_GREEN)
    ]

    for idx, (val, lbl, col) in enumerate(metrics):
        left = 0.8 + idx * 2.98
        create_card(slide5, left, 1.8, 2.8, 1.4)
        tb = slide5.shapes.add_textbox(Inches(left + 0.1), Inches(1.9), Inches(2.6), Inches(1.2))
        tf = tb.text_frame
        tf.word_wrap = True

        p1 = tf.paragraphs[0]
        p1.text = val
        p1.font.size = Pt(22)
        p1.font.bold = True
        p1.font.color.rgb = col
        p1.alignment = PP_ALIGN.CENTER

        p2 = tf.add_paragraph()
        p2.text = lbl
        p2.font.size = Pt(11)
        p2.font.color.rgb = TEXT_MUTED
        p2.alignment = PP_ALIGN.CENTER
        p2.space_before = Pt(4)

    # Classification Breakdown Card
    create_card(slide5, 0.8, 3.4, 11.733, 3.4)
    tb_t = slide5.shapes.add_textbox(Inches(1.1), Inches(3.6), Inches(11.1), Inches(3.0))
    tf_t = tb_t.text_frame
    tf_t.word_wrap = True

    pt1 = tf_t.paragraphs[0]
    pt1.text = "📊 ATTACK CATEGORY CLASSIFICATION BREAKDOWN"
    pt1.font.size = Pt(15)
    pt1.font.bold = True
    pt1.font.color.rgb = ACCENT_GREEN

    rows_data = [
        ("BENIGN / NORMAL", "0.99 Precision | 0.99 Recall | 0.99 F1-Score", "Standard clean network flow activity"),
        ("DOS / DDOS ATTACKS", "0.98 Precision | 0.99 Recall | 0.98 F1-Score", "High-volume TCP/UDP/HTTP flooding"),
        ("BRUTE FORCE", "0.95 Precision | 0.92 Recall | 0.93 F1-Score", "SSH / FTP dictionary credential attacks"),
        ("WEB ATTACKS", "0.87 Precision | 0.85 Recall | 0.86 F1-Score", "SQL Injection, Cross-Site Scripting (XSS)"),
        ("ZERO-DAY ANOMALIES", "Isolation Forest Engine (Contamination=0.03)", "Novel statistical flow deviation detection")
    ]

    for cat, stat, note in rows_data:
        p_row = tf_t.add_paragraph()
        p_row.text = f"• {cat}: "
        p_row.font.bold = True
        p_row.font.size = Pt(13)
        p_row.font.color.rgb = TEXT_MAIN
        p_row.space_before = Pt(6)

        r_stat = p_row.add_run()
        r_stat.text = f"{stat}  —  "
        r_stat.font.bold = True
        r_stat.font.color.rgb = ACCENT_BLUE

        r_note = p_row.add_run()
        r_note.text = note
        r_note.font.bold = False
        r_note.font.color.rgb = TEXT_MUTED


    # ==========================================
    # SLIDE 6: EXPLAINABLE AI & GENAI COPILOT
    # ==========================================
    slide6 = prs.slides.add_slide(blank_layout)
    add_background(slide6)
    add_header(slide6, "Explainable AI (XAI) & GenAI Security Copilot")

    # Left Card: Explainable AI
    create_card(slide6, 0.8, 1.8, 5.6, 5.0)
    tb_x = slide6.shapes.add_textbox(Inches(1.1), Inches(2.0), Inches(5.0), Inches(4.5))
    tf_x = tb_x.text_frame
    tf_x.word_wrap = True

    p = tf_x.paragraphs[0]
    p.text = "🔍 EXPLAINABLE AI (SHAP ENGINE)"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_PURPLE

    xai_points = [
        ("Transparent Predictions", "Bypasses the 'black box' problem by computing feature importance per classification."),
        ("Key Feature Breakdown", "Highlights critical indicators like Flow Duration, Packet Rate, Header Length, and TCP Flags."),
        ("Security Analyst Trust", "Allows analysts to verify why a specific IP or packet was flagged before taking containment action.")
    ]

    for title, desc in xai_points:
        p_t = tf_x.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = TEXT_MAIN
        p_t.space_before = Pt(14)

        run = p_t.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED

    # Right Card: GenAI Copilot
    create_card(slide6, 6.8, 1.8, 5.7, 5.0)
    tb_c = slide6.shapes.add_textbox(Inches(7.1), Inches(2.0), Inches(5.1), Inches(4.5))
    tf_c = tb_c.text_frame
    tf_c.word_wrap = True

    p = tf_c.paragraphs[0]
    p.text = "🤖 GENAI SECURITY ASSISTANT"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_GREEN

    copilot_points = [
        ("Interactive Copilot Chat", "Natural language query interface to ask questions about active network health and incidents."),
        ("Automated Threat Briefings", "Synthesizes raw detection logs into structured executive threat briefings via /assistant/insights."),
        ("Instant Remediation Advice", "Provides actionable steps for mitigating detected vulnerabilities in industrial IoT environments.")
    ]

    for title, desc in copilot_points:
        p_t = tf_c.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = TEXT_MAIN
        p_t.space_before = Pt(14)

        run = p_t.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED


    # ==========================================
    # SLIDE 7: AUTOMATED CONTAINMENT & LICENSING
    # ==========================================
    slide7 = prs.slides.add_slide(blank_layout)
    add_background(slide7)
    add_header(slide7, "Automated Threat Containment & Product Licensing")

    # Left Card: Auto Containment
    create_card(slide7, 0.8, 1.8, 5.6, 5.0)
    tb_cont = slide7.shapes.add_textbox(Inches(1.1), Inches(2.0), Inches(5.0), Inches(4.5))
    tf_cont = tb_cont.text_frame
    tf_cont.word_wrap = True

    p = tf_cont.paragraphs[0]
    p.text = "🚫 AUTOMATED FIREWALL CONTAINMENT"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_AMBER

    c_points = [
        ("Multi-OS Support", "Executes automated dynamic rules via netsh advfirewall (Windows) and iptables (Linux)."),
        ("Threshold Triggering", "Automatically blocks offending source IPs when attack confidence exceeds 95% threshold."),
        ("Safety Whitelisting", "Protects loopback, local gateway, and corporate DNS servers from accidental locking."),
        ("Audit Trail", "Maintains detailed block/unblock timestamps, analyst actions, and reason codes.")
    ]

    for title, desc in c_points:
        p_t = tf_cont.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = TEXT_MAIN
        p_t.space_before = Pt(12)

        run = p_t.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED

    # Right Card: Cryptographic Licensing
    create_card(slide7, 6.8, 1.8, 5.7, 5.0)
    tb_lic = slide7.shapes.add_textbox(Inches(7.1), Inches(2.0), Inches(5.1), Inches(4.5))
    tf_lic = tb_lic.text_frame
    tf_lic.word_wrap = True

    p = tf_lic.paragraphs[0]
    p.text = "🔑 CRYPTOGRAPHIC PRODUCT LICENSING"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_BLUE

    l_points = [
        ("RSA / Ed25519 Security", "Uses cryptographically signed license keys to verify authenticity and prevent tampering."),
        ("Tiered Feature Gating", "Supports Trial, Professional, and Enterprise license tiers with feature-level middleware enforcement."),
        ("Hardware Binding", "Enforces hardware fingerprinting and expiration tracking across API endpoints."),
        ("License Management", "Provides dedicated API routes and UI panels to check status and activate valid keys.")
    ]

    for title, desc in l_points:
        p_t = tf_lic.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = TEXT_MAIN
        p_t.space_before = Pt(12)

        run = p_t.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED


    # ==========================================
    # SLIDE 8: TECH STACK & SECURITY ARCHITECTURE
    # ==========================================
    slide8 = prs.slides.add_slide(blank_layout)
    add_background(slide8)
    add_header(slide8, "Technology Stack & Enterprise Security")

    # Left Card: Technology Stack
    create_card(slide8, 0.8, 1.8, 5.6, 5.0)
    tb_tech = slide8.shapes.add_textbox(Inches(1.1), Inches(2.0), Inches(5.0), Inches(4.5))
    tf_tech = tb_tech.text_frame
    tf_tech.word_wrap = True

    p = tf_tech.paragraphs[0]
    p.text = "💻 TECHNOLOGY STACK"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_BLUE

    tech_stack = [
        ("Backend Framework", "Python 3.11, FastAPI (v0.111), Uvicorn"),
        ("Frontend Dashboard", "React 19.0, Vite, Lucide Icons, Recharts"),
        ("ML Libraries", "XGBoost, Scikit-learn, SHAP, Imbalanced-learn"),
        ("Database Layer", "SQLite WAL Mode + Neon Cloud PostgreSQL"),
        ("Buffering & Packet Engine", "Redis Streams, Scapy 2.5, Nmap 7.99")
    ]

    for title, desc in tech_stack:
        p_t = tf_tech.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = TEXT_MAIN
        p_t.space_before = Pt(12)

        run = p_t.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED

    # Right Card: Security & Compliance
    create_card(slide8, 6.8, 1.8, 5.7, 5.0)
    tb_sec = slide8.shapes.add_textbox(Inches(7.1), Inches(2.0), Inches(5.1), Inches(4.5))
    tf_sec = tb_sec.text_frame
    tf_sec.word_wrap = True

    p = tf_sec.paragraphs[0]
    p.text = "🛡️ SECURITY & COMPLIANCE"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_GREEN

    sec_points = [
        ("Password Hashing", "PBKDF2-HMAC-SHA256 with 260,000 hashing iterations for user accounts."),
        ("JWT Auth & RBAC", "JSON Web Tokens with role-based access control (Admin, Analyst, Viewer)."),
        ("Rate Limiting", "Automatic 15-minute account lockout following 5 consecutive failed login attempts."),
        ("Encrypted Cloud Sync", "SSL-encrypted connections for Neon Cloud PostgreSQL sync.")
    ]

    for title, desc in sec_points:
        p_t = tf_sec.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = TEXT_MAIN
        p_t.space_before = Pt(12)

        run = p_t.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED


    # ==========================================
    # SLIDE 9: REPOSITORY STRUCTURE & QUICK START
    # ==========================================
    slide9 = prs.slides.add_slide(blank_layout)
    add_background(slide9)
    add_header(slide9, "Deployment & Repository Structure")

    # Left Card: Directory Layout
    create_card(slide9, 0.8, 1.8, 5.6, 5.0)
    tb_dir = slide9.shapes.add_textbox(Inches(1.1), Inches(2.0), Inches(5.0), Inches(4.5))
    tf_dir = tb_dir.text_frame
    tf_dir.word_wrap = True

    p = tf_dir.paragraphs[0]
    p.text = "📁 CORE DIRECTORY STRUCTURE"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_PURPLE

    dirs = [
        ("api/main.py", "FastAPI app, REST endpoints & cloud sync worker"),
        ("src/predict.py", "Dual-ML model inference (XGBoost + Zero-Day)"),
        ("src/capture.py", "Scapy flow extractor & 2-second packet flusher"),
        ("src/database.py", "Dual DB engine (SQLite WAL & PostgreSQL)"),
        ("react-dashboard/", "React 19 real-time cybersecurity interface"),
        ("run-netguard.ps1", "1-click automated PowerShell launcher script")
    ]

    for title, desc in dirs:
        p_t = tf_dir.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(12)
        p_t.font.color.rgb = TEXT_MAIN
        p_t.space_before = Pt(8)

        run = p_t.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED

    # Right Card: Quick Start Commands
    create_card(slide9, 6.8, 1.8, 5.7, 5.0)
    tb_qs = slide9.shapes.add_textbox(Inches(7.1), Inches(2.0), Inches(5.1), Inches(4.5))
    tf_qs = tb_qs.text_frame
    tf_qs.word_wrap = True

    p = tf_qs.paragraphs[0]
    p.text = "🚀 QUICK START & DEPLOYMENT"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_AMBER

    qs_points = [
        ("1-Click Launch Script", "Run .\\run-netguard.ps1 in Admin PowerShell to automatically start backend and frontend services."),
        ("Manual Backend API", "uvicorn api.main:app --host 0.0.0.0 --port 8081"),
        ("Manual Frontend Dashboard", "cd react-dashboard && npm run dev (Port 5174)"),
        ("24/7 Production Deployment", "Runs permanently as Windows Background Services via NSSM (NetGuard-API, NetGuard-React).")
    ]

    for title, desc in qs_points:
        p_t = tf_qs.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = TEXT_MAIN
        p_t.space_before = Pt(12)

        run = p_t.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED


    # ==========================================
    # SLIDE 10: CONCLUSION & FUTURE ROADMAP
    # ==========================================
    slide10 = prs.slides.add_slide(blank_layout)
    add_background(slide10)
    add_header(slide10, "Future Roadmap & Conclusion")

    # Left Card: Roadmap
    create_card(slide10, 0.8, 1.8, 5.6, 5.0)
    tb_rd = slide10.shapes.add_textbox(Inches(1.1), Inches(2.0), Inches(5.0), Inches(4.5))
    tf_rd = tb_rd.text_frame
    tf_rd.word_wrap = True

    p = tf_rd.paragraphs[0]
    p.text = "🔮 FUTURE DEVELOPMENT ROADMAP"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_GREEN

    phases = [
        ("Phase 2: eBPF Packet Capture", "Migrate to eBPF/XDP on Linux for sub-microsecond kernel packet processing."),
        ("SIEM / SOAR Connectors", "Native Syslog & Webhook exporters for Splunk, Elastic Security (ELK), and Sentinel."),
        ("Phase 3: Deep Learning Models", "Train LSTM / Temporal Fusion Transformers for multi-step attack campaign prediction."),
        ("Hardware Acceleration", "NVIDIA TensorRT acceleration for line-rate 10Gbps+ network inference.")
    ]

    for title, desc in phases:
        p_t = tf_rd.add_paragraph()
        p_t.text = f"• {title}: "
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = TEXT_MAIN
        p_t.space_before = Pt(12)

        run = p_t.add_run()
        run.text = desc
        run.font.bold = False
        run.font.color.rgb = TEXT_MUTED

    # Right Card: Conclusion & Contact
    create_card(slide10, 6.8, 1.8, 5.7, 5.0, bg_color=CARD_BG, border_color=ACCENT_BLUE)
    tb_ccl = slide10.shapes.add_textbox(Inches(7.1), Inches(2.0), Inches(5.1), Inches(4.5))
    tf_ccl = tb_ccl.text_frame
    tf_ccl.word_wrap = True

    p = tf_ccl.paragraphs[0]
    p.text = "🎓 CONCLUSION & ACKNOWLEDGEMENTS"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = ACCENT_BLUE

    p_summary = tf_ccl.add_paragraph()
    p_summary.text = "NetGuard IDS v2.2 delivers a complete, production-ready, AI-driven IoT Network Detection and Response platform bridging raw packet capture with explainable intelligence."
    p_summary.font.size = Pt(13)
    p_summary.font.color.rgb = TEXT_MAIN
    p_summary.space_before = Pt(12)

    p_ct = tf_ccl.add_paragraph()
    p_ct.text = "📬 Contact Information & Project Repository:"
    p_ct.font.size = Pt(14)
    p_ct.font.bold = True
    p_ct.font.color.rgb = ACCENT_PURPLE
    p_ct.space_before = Pt(20)

    p_info = tf_ccl.add_paragraph()
    p_info.text = "• Presenter: Nikhil Dehariya (B.Tech AIDS, JNCT Bhopal)\n• Email: nikhildehariya101@gmail.com\n• Mentor: [Mentor / Guide Name]\n• Repository: github.com/nikhildehariya/netguard-ids"
    p_info.font.size = Pt(12)
    p_info.font.color.rgb = TEXT_MUTED
    p_info.space_before = Pt(8)

    p_ty = tf_ccl.add_paragraph()
    p_ty.text = "Thank You! Questions & Answers"
    p_ty.font.size = Pt(18)
    p_ty.font.bold = True
    p_ty.font.color.rgb = ACCENT_GREEN
    p_ty.alignment = PP_ALIGN.CENTER
    p_ty.space_before = Pt(24)

    # Save output
    output_path = os.path.abspath("NetGuard_IDS_v2.2_Presentation.pptx")
    prs.save(output_path)
    print(f"Presentation successfully created at: {output_path}")

if __name__ == "__main__":
    create_presentation()
