// GLOBAL VARIABLES
let previousStatus = "SECURE";
let entropyChartInstance = null;
let ioChartInstance = null;

// Initialize global data container for graphs
window.lastGraphData = {
    entropy: Array(60).fill(0),
    io: Array(60).fill(0)
};

document.addEventListener('DOMContentLoaded', () => {
    // Start the loop when the page loads
    setInterval(updateStatus, 1000);
});

function updateStatus() {
    fetch('/api/status')
    .then(response => response.json())
    .then(data => {
        // --- 1. UPDATE BASIC METRICS ---
        document.getElementById('io-rate').innerText = data.rate;
        document.getElementById('io-bar').style.width = Math.min(data.rate, 100) + "%";
        
        // Color change for high I/O
        if(data.rate > 50) document.getElementById('io-bar').style.backgroundColor = "var(--neon-red)";
        else document.getElementById('io-bar').style.backgroundColor = "var(--neon-cyan)";
        
        document.getElementById('entropy-val').innerText = data.entropy.toFixed(2);
        document.getElementById('ent-bar').style.width = (data.entropy * 10) + "%";
        
        document.getElementById('ai-conf').innerText = data.ai_conf + "%";
        document.getElementById('ai-bar').style.width = data.ai_conf + "%";

        document.getElementById('status-text').innerText = data.status;
        document.getElementById('sub-status').innerText = data.message;

        // --- 2. UPDATE THREAT ORIGIN (AI HUNT) ---
        const pathLabel = document.getElementById('malware-path');
        const pidLabel = document.getElementById('malware-pid');
        const reasonLabel = document.getElementById('ai-reason');

        // Safety Check: Use defaults if data is missing
        const safePath = data.malware_path || "SYSTEM CLEAN"; 
        const safePid = data.malware_pid || "PID: ---";
        const safeReason = data.ai_reason || "NEURAL NET STANDBY";

        if (data.status === "DANGER") {
            pathLabel.innerText = safePath; 
            pidLabel.innerText = safePid;
            reasonLabel.innerText = safeReason;
            
            // Turn text RED
            pathLabel.style.color = "var(--neon-red)";
            pidLabel.style.color = "var(--neon-red)";
            pidLabel.style.fontWeight = "bold";
            reasonLabel.style.color = "var(--neon-cyan)";
        } else {
            // Reset to Green/White
            pathLabel.innerText = "SYSTEM CLEAN";
            pidLabel.innerText = "PID: ---";
            reasonLabel.innerText = "NEURAL NET STANDBY";
            
            pathLabel.style.color = "#fff";
            pidLabel.style.color = "var(--neon-green)";
            reasonLabel.style.color = "#666";
        }

        // --- 3. UPDATE AI SCORE BREAKDOWN ---
        const hScore = data.ai_score_breakdown.heuristics;
        const eScore = data.ai_score_breakdown.entropy;
        const bScore = data.ai_score_breakdown.behavior;

        document.getElementById('score-heuristics').innerText = hScore;
        document.getElementById('score-entropy').innerText = eScore;
        document.getElementById('score-behavior').innerText = bScore;

        // Dynamic Colors for Scores (Red if > 50)
        document.getElementById('score-heuristics').style.color = hScore > 50 ? "var(--neon-red)" : "var(--neon-green)";
        document.getElementById('score-entropy').style.color = eScore > 50 ? "var(--neon-red)" : "var(--neon-green)";
        document.getElementById('score-behavior').style.color = bScore > 50 ? "var(--neon-red)" : "var(--neon-green)";

        // --- 4. VISUAL STATE CHANGES ---
        const ring = document.getElementById('status-ring');
        const killBtn = document.getElementById('eliminate-btn');

        if (data.status === "DANGER") {
            ring.className = "status-ring danger";
            killBtn.style.display = "inline-block"; 
            previousStatus = "DANGER";
        } else if (data.status === "WARNING") {
            ring.className = "status-ring warning";
            previousStatus = "WARNING";
        } else {
            ring.className = "status-ring secure";
            previousStatus = "SECURE";
        }

        // Store graph data for the report modal
        window.lastGraphData = {
            entropy: data.graph_entropy,
            io: data.graph_io
        };
    })
    .catch(err => console.error("API Error:", err));
}

// --- BUTTON FUNCTIONS ---

function eliminateThreat() {
    const btn = document.getElementById('eliminate-btn');
    btn.disabled = true;
    btn.innerText = "PURGING...";
    
    fetch('/api/eliminate', { method: 'POST' })
    .then(res => res.json())
    .then(data => {
        alert(data.message);
        document.getElementById('eliminate-btn').style.display = 'none';
        document.getElementById('report-btn').style.display = "inline-block";
    });
}

function generateReport() {
    document.getElementById('report-modal').style.display = "block";
    const reportDiv = document.getElementById('report-content');
    reportDiv.innerHTML = "> ESTABLISHING UPLINK WITH GROQ NEURAL NET...";
    
    // Draw the graphs inside the modal
    renderGraphs();

    fetch('/api/report')
    .then(res => res.json())
    .then(data => {
        reportDiv.innerHTML = data.report;
    });
}

function closeReport() {
    document.getElementById('report-modal').style.display = "none";
}

function resetSystem() {
    fetch('/api/reset', { method: 'POST' })
    .then(() => {
        previousStatus = "SECURE";
        document.getElementById('report-btn').style.display = "none";
        const killBtn = document.getElementById('eliminate-btn');
        killBtn.disabled = false;
        killBtn.innerText = "☠️ ELIMINATE THREAT";
        killBtn.style.display = "none";
        alert("SYSTEM RESET COMPLETE. MONITORING ACTIVE.");
    });
}

// --- CHART.JS LOGIC ---
function renderGraphs() {
    const data = window.lastGraphData;
    const labels = Array.from({length: 60}, (_, i) => i);
    
    const commonOptions = {
        responsive: true, 
        maintainAspectRatio: false, 
        plugins: { legend: { display: false } }, 
        scales: { 
            x: { display: false }, 
            y: { grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: '#888' } } 
        } 
    };

    // Destroy old charts if they exist to prevent memory leaks
    if (entropyChartInstance) entropyChartInstance.destroy();
    if (ioChartInstance) ioChartInstance.destroy();

    // 1. Entropy Chart
    const ctxEnt = document.getElementById('entropyChart').getContext('2d');
    entropyChartInstance = new Chart(ctxEnt, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                data: data.entropy,
                borderColor: '#00ff41', // Neon Green
                backgroundColor: 'rgba(0, 255, 65, 0.1)',
                fill: true,
                tension: 0.4, // Smooth curve
                pointRadius: 0
            }]
        },
        options: { ...commonOptions, scales: { ...commonOptions.scales, y: { max: 9, min: 0 } } }
    });

    // 2. I/O Chart
    const ctxIO = document.getElementById('ioChart').getContext('2d');
    ioChartInstance = new Chart(ctxIO, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                data: data.io,
                borderColor: '#ff2a2a', // Neon Red
                backgroundColor: 'rgba(255, 42, 42, 0.1)',
                fill: true,
                tension: 0.1,
                pointRadius: 0
            }]
        },
        options: commonOptions
    });
}