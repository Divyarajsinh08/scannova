// ===== GET SCAN RESULT FROM LOCALSTORAGE =====
const scanResult = JSON.parse(localStorage.getItem('scanResult'));

// ===== LOAD RESULTS WHEN PAGE OPENS =====
window.onload = function() {
    if (!scanResult) {
        window.location.href = 'index.html';
        return;
    }
    displayResults(scanResult);
}

// ===== DISPLAY RESULTS =====
function displayResults(data) {

    // ===== HANDLE BACKEND / VIRUSTOTAL ERRORS FIRST =====
    // If the backend couldn't get a real result (bad/rate-limited API key,
    // VT quota exceeded, analysis timed out, etc.) it returns an `error`
    // field alongside malicious:0/suspicious:0/clean:0. Those zeros are NOT
    // a real "clean" verdict - they just mean "we don't know". Showing
    // "SAFE" in that case is misleading, so we short-circuit here instead
    // of falling through to the normal safe/suspicious/dangerous logic.
    if (data.error) {
        const verdictBox = document.getElementById('verdictBox');
        verdictBox.classList.add('verdict-error');
        document.getElementById('verdictIcon').className = 'fas fa-exclamation-circle';
        document.getElementById('verdictText').textContent = '⚠️ SCAN FAILED';
        document.getElementById('verdictDesc').textContent =
            data.error + ' — this is NOT a "safe" result, the scan could not be completed.';

        document.getElementById('infoFileName').textContent = data.file_name || '-';
        document.getElementById('infoFileSize').textContent = data.file_size || '-';
        document.getElementById('infoFileType').textContent = data.file_type || '-';
        document.getElementById('infoScanDate').textContent = new Date().toLocaleString();

        document.getElementById('maliciousCount').textContent = '?';
        document.getElementById('suspiciousCount').textContent = '?';
        document.getElementById('cleanCount').textContent = '?';

        document.getElementById('scoreNumber').textContent = '?';
        return; // don't run the safe/suspicious/dangerous scoring below
    }

    // File Information
    document.getElementById('infoFileName').textContent = data.file_name || '-';
    document.getElementById('infoFileSize').textContent = data.file_size || '-';
    document.getElementById('infoFileType').textContent = data.file_type || '-';
    document.getElementById('infoScanDate').textContent = new Date().toLocaleString();

    // Detection Stats
    const malicious = data.malicious || 0;
    const suspicious = data.suspicious || 0;
    const clean = data.clean || 0;

    document.getElementById('maliciousCount').textContent = malicious;
    document.getElementById('suspiciousCount').textContent = suspicious;
    document.getElementById('cleanCount').textContent = clean;

    // Threat Score Calculation
    const total = malicious + suspicious + clean;
    let score = 0;
    if (total > 0) {
        score = Math.round(((malicious * 1.0 + suspicious * 0.5) / total) * 100);
    }
    document.getElementById('scoreNumber').textContent = score;

    // Score Circle Color
    const scoreCircle = document.getElementById('scoreCircle');
    if (score >= 50) {
        scoreCircle.style.borderColor = '#ff4444';
        scoreCircle.style.backgroundColor = '#1f0d0d';
        document.getElementById('scoreNumber').style.color = '#ff4444';
    } else if (score >= 20) {
        scoreCircle.style.borderColor = '#ffaa00';
        scoreCircle.style.backgroundColor = '#1f1a0d';
        document.getElementById('scoreNumber').style.color = '#ffaa00';
    }

    // Verdict
    const verdictBox = document.getElementById('verdictBox');
    const verdictIcon = document.getElementById('verdictIcon');
    const verdictText = document.getElementById('verdictText');
    const verdictDesc = document.getElementById('verdictDesc');

    if (malicious > 0) {
        verdictBox.classList.add('verdict-dangerous');
        verdictIcon.className = 'fas fa-times-circle';
        verdictText.textContent = '❌ DANGEROUS';
        verdictDesc.textContent = 'This file is malicious! Do not open or use it.';
    } else if (suspicious > 0) {
        verdictBox.classList.add('verdict-suspicious');
        verdictIcon.className = 'fas fa-exclamation-triangle';
        verdictText.textContent = '⚠️ SUSPICIOUS';
        verdictDesc.textContent = 'This file looks suspicious. Be careful!';
    } else {
        verdictBox.classList.add('verdict-safe');
        verdictIcon.className = 'fas fa-check-circle';
        verdictText.textContent = '✅ SAFE';
        verdictDesc.textContent = 'No threats detected! This file appears to be safe.';
    }
}

// ===== DOWNLOAD PDF REPORT =====
function downloadReport() {
    if (scanResult && scanResult.error) {
        alert('⚠️ Cannot generate a report: the scan did not complete successfully.\n\n' + scanResult.error);
        return;
    }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    // Title
    doc.setFontSize(22);
    doc.setTextColor(0, 255, 136);
    doc.text('Scannova - Security Scan Report', 20, 20);

    // Date
    doc.setFontSize(11);
    doc.setTextColor(150, 150, 150);
    doc.text('Scan Date: ' + new Date().toLocaleString(), 20, 30);

    // Divider
    doc.setDrawColor(0, 255, 136);
    doc.line(20, 35, 190, 35);

    // File Info
    doc.setFontSize(14);
    doc.setTextColor(255, 255, 255);
    doc.text('File Information:', 20, 45);

    doc.setFontSize(11);
    doc.setTextColor(200, 200, 200);
    doc.text('File Name : ' + (scanResult.file_name || '-'), 20, 55);
    doc.text('File Size : ' + (scanResult.file_size || '-'), 20, 63);
    doc.text('File Type : ' + (scanResult.file_type || '-'), 20, 71);

    // Detection
    doc.setFontSize(14);
    doc.setTextColor(255, 255, 255);
    doc.text('Detection Results:', 20, 85);

    doc.setFontSize(11);
    doc.setTextColor(255, 68, 68);
    doc.text('Malicious  : ' + (scanResult.malicious || 0), 20, 95);

    doc.setTextColor(255, 170, 0);
    doc.text('Suspicious : ' + (scanResult.suspicious || 0), 20, 103);

    doc.setTextColor(0, 255, 136);
    doc.text('Clean      : ' + (scanResult.clean || 0), 20, 111);

    // Verdict
    doc.setFontSize(16);
    doc.setTextColor(255, 255, 255);
    doc.text('Verdict: ' + document.getElementById('verdictText').textContent, 20, 125);

    // Footer
    doc.setFontSize(10);
    doc.setTextColor(100, 100, 100);
    doc.text('Generated by Scannova | Built by Parmar Divyarajsinh', 20, 280);

    // Save PDF
    doc.save('scannova-report.pdf');
}