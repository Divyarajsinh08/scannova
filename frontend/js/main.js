// ===== FILE SELECTION =====
const fileInput = document.getElementById('fileInput');
const fileName = document.getElementById('fileName');
const uploadBox = document.getElementById('uploadBox');
const scanBtn = document.getElementById('scanBtn');
const loading = document.getElementById('loading');
const cancelBtn = document.getElementById('cancelBtn');

// Safety check
if (scanBtn) scanBtn.style.display = 'none';
if (cancelBtn) cancelBtn.style.display = 'none';

// Show file name when selected
fileInput.addEventListener('change', function() {
    if (fileInput.files.length > 0) {
        showFile(fileInput.files[0].name);
    }
});

// ===== SHOW FILE =====
function showFile(name) {
    fileName.textContent = '✅ ' + name;
    scanBtn.style.display = 'inline-block';
    cancelBtn.style.display = 'inline-block';
    uploadBox.style.borderColor = '#00ff88';
    uploadBox.style.backgroundColor = '#0d1f17';
}

// ===== CANCEL FILE =====
function cancelFile() {
    fileInput.value = '';
    fileName.textContent = 'No file chosen';
    scanBtn.style.display = 'none';
    cancelBtn.style.display = 'none';
    uploadBox.style.borderColor = '#00ff88';
    uploadBox.style.backgroundColor = '#111';
    loading.style.display = 'none';
    scanBtn.disabled = false;
    scanBtn.textContent = '🔍 Scan Now';
}

// ===== DRAG & DROP =====
uploadBox.addEventListener('dragover', function(e) {
    e.preventDefault();
    uploadBox.style.borderColor = '#00cc6a';
    uploadBox.style.backgroundColor = '#0d2b1a';
});

uploadBox.addEventListener('dragleave', function() {
    uploadBox.style.borderColor = '#00ff88';
    uploadBox.style.backgroundColor = '#111';
});

uploadBox.addEventListener('drop', function(e) {
    e.preventDefault();
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        fileInput.files = files;
        showFile(files[0].name);
    }
});

// ===== SCAN FILE =====
async function scanFile() {
    if (!fileInput.files.length) {
        alert('⚠️ Please select a file first!');
        return;
    }

    const file = fileInput.files[0];

    if (file.size > 32 * 1024 * 1024) {
        alert('⚠️ File size must be less than 32MB!');
        return;
    }

    // Show loading
    loading.style.display = 'block';
    scanBtn.disabled = true;
    scanBtn.textContent = 'Scanning...';
    if (cancelBtn) cancelBtn.style.display = 'none';

    try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch('http://127.0.0.1:5000/scan', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        localStorage.setItem('scanResult', JSON.stringify(result));
        window.location.href = 'result.html';

    } catch (error) {
        loading.style.display = 'none';
        scanBtn.disabled = false;
        scanBtn.textContent = '🔍 Scan Now';
        if (cancelBtn) cancelBtn.style.display = 'inline-block';
        alert('❌ Error connecting to server! Make sure backend is running.');
    }
}