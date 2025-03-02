document.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname;

    if (path === '/login') {
        handleLogin();
    } else if (path === '/register') {
        handleRegister();
    } else if (path === '/') {
        fetchDocuments();
        handleUpload();
        handleLogout();
        initializeFAB();
    } else if (path === '/user/profile') {
        console.log('Profile page loaded - initializing');
        fetchUserInfoWithRetry();
        handleRequestCredits();
        handleViewRequests();
        handleViewAnalytics();
        handleLogout();
        initializeFAB();
    } else if (path === '/user/documents') {
        fetchAllDocuments();
        handleLogout();
        initializeFAB();
    } else if (path === '/admin/analytics') {
        handleLogout();
        initializeFAB();
    }
});

async function fetchUserInfoWithRetry(attempts = 3, delay = 1000) {
    for (let i = 0; i < attempts; i++) {
        try {
            const response = await fetch('/user/credits');
            if (!response.ok) throw new Error('Failed to fetch user info');
            const data = await response.json();
            console.log('User Info Response:', data);

            const userInfoEl = document.getElementById('userInfo');
            if (userInfoEl) {
                userInfoEl.textContent = `Welcome, ${data.username || 'User'}! Credits: ${data.credits}`;
            }

            if (window.location.pathname === '/user/profile') {
                console.log('Updating profile page elements');
                const usernameDisplay = document.getElementById('usernameDisplay');
                const creditsDisplay = document.getElementById('creditsDisplay');
                const viewRequestsBtn = document.getElementById('viewRequests');
                const viewAnalyticsBtn = document.getElementById('viewAnalytics');

                if (usernameDisplay) usernameDisplay.textContent = `Username: ${data.username || 'User'}`;
                if (creditsDisplay) creditsDisplay.textContent = `Credits: ${data.credits}`;

                // Check if the user is an admin via the new endpoint
                const adminResponse = await fetch('/user/is_admin');
                if (!adminResponse.ok) throw new Error('Failed to fetch admin status');
                const adminData = await adminResponse.json();
                console.log('Is Admin Response:', adminData);

                if (adminData.is_admin) {
                    console.log('Admin detected - showing buttons');
                    if (viewRequestsBtn) viewRequestsBtn.style.display = 'block';
                    if (viewAnalyticsBtn) viewAnalyticsBtn.style.display = 'block';
                } else {
                    console.log('Not admin - hiding buttons');
                    if (viewRequestsBtn) viewRequestsBtn.style.display = 'none';
                    if (viewAnalyticsBtn) viewAnalyticsBtn.style.display = 'none';
                }
            }
            return; // Success, exit the retry loop
        } catch (error) {
            console.error(`Attempt ${i + 1} failed: ${error.message}`);
            if (i < attempts - 1) {
                console.log(`Retrying in ${delay}ms...`);
                await new Promise(resolve => setTimeout(resolve, delay));
            } else {
                console.error('All attempts failed to fetch user info.');
            }
        }
    }
}

function handleLogin() {
    const form = document.getElementById('loginForm');
    const messageEl = document.getElementById('loginMessage');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        try {
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const result = await response.json();

            messageEl.textContent = response.ok ? result.message : result.error;
            messageEl.style.color = response.ok ? '#4CAF50' : '#F44336';

            if (response.ok) window.location.href = '/';
        } catch (error) {
            messageEl.textContent = `Error: ${error.message}`;
            messageEl.style.color = '#F44336';
        }
    });
}

function handleRegister() {
    const form = document.getElementById('registerForm');
    const messageEl = document.getElementById('registerMessage');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        try {
            const response = await fetch('/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const result = await response.json();

            messageEl.textContent = response.ok ? result.message : result.error;
            messageEl.style.color = response.ok ? '#4CAF50' : '#F44336';

            if (response.ok) setTimeout(() => window.location.href = '/login', 1000);
        } catch (error) {
            messageEl.textContent = `Error: ${error.message}`;
            messageEl.style.color = '#F44336';
        }
    });
}

function handleUpload() {
    const form = document.getElementById('uploadForm');
    const messageEl = document.getElementById('uploadMessage');
    const matchesSection = document.getElementById('matchesSection');
    const matchesList = document.getElementById('matchesList');
    const creditsEl = document.querySelector('header p');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const fileInput = document.getElementById('fileInput');
        const file = fileInput.files[0];
        const useAi = document.getElementById('aiCheck').checked;
        console.log("AI Check enabled:", useAi);

        if (!file) {
            messageEl.textContent = 'Please select a file.';
            messageEl.style.color = '#F44336';
            return;
        }

        const formData = new FormData();
        formData.append('file', file);
        formData.append('use_ai', useAi);
        console.log("Form data use_ai:", useAi);

        try {
            const response = await fetch('/upload', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();

            messageEl.textContent = response.ok ? result.message : result.error;
            messageEl.style.color = response.ok ? '#4CAF50' : '#F44336';

            if (response.ok) {
                fileInput.value = '';
                // Update sessionDocs with the new document
                const sessionDocs = JSON.parse(sessionStorage.getItem('sessionDocs') || '[]');
                const newDoc = {
                    id: result.matches.find(m => m.filename === result.filename)?.id || Date.now(), // Fallback ID
                    filename: result.filename,
                    upload_date: new Date().toISOString() // Approximate upload date
                };
                sessionDocs.push(newDoc);
                sessionStorage.setItem('sessionDocs', JSON.stringify(sessionDocs));
                fetchDocuments();
                if (result.matches && result.matches.length > 0) {
                    matchesList.innerHTML = '';
                    result.matches.forEach(match => {
                        const details = document.createElement('details');
                        details.innerHTML = `
                            <summary>${match.filename} (Similarity: ${(match.similarity * 100).toFixed(2)}%)</summary>
                            <p><a href="/download/${match.id}">Download</a> ${result.ai_used ? '<span style="color: #4CAF50;">AI-Powered Match</span>' : ''}</p>
                        `;
                        matchesList.appendChild(details);
                    });
                    matchesSection.style.display = 'block';
                } else {
                    matchesSection.style.display = 'none';
                }
                const creditsResponse = await fetch('/user/credits');
                const creditsData = await creditsResponse.json();
                if (creditsResponse.ok) {
                    const username = creditsEl.textContent.split('! Credits:')[0].replace('Welcome, ', '');
                    creditsEl.textContent = `Welcome, ${username}! Credits: ${creditsData.credits}`;
                }
            }
        } catch (error) {
            messageEl.textContent = `Error: ${error.message}`;
            messageEl.style.color = '#F44336';
        }
    });
}

async function fetchDocuments() {
    try {
        const response = await fetch('/documents');
        const documents = await response.json();
        const docList = document.getElementById('docList');

        if (!response.ok) {
            window.location.href = '/login';
            return;
        }

        const sessionDocs = JSON.parse(sessionStorage.getItem('sessionDocs') || '[]');
        docList.innerHTML = '';
        documents.filter(doc => sessionDocs.some(sd => sd.filename === doc.filename)).forEach(doc => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${doc.id}</td>
                <td>${doc.filename}</td>
                <td>${new Date(doc.upload_date).toLocaleString()}</td>
                <td>
                    <button class="download" onclick="downloadFile(${doc.id})">Download</button>
                    <button class="delete" onclick="deleteFile(${doc.id})">Delete</button>
                </td>
            `;
            docList.appendChild(row);
        });
    } catch (error) {
        console.error('Error fetching documents:', error);
        window.location.href = '/login';
    }
}

async function fetchAllDocuments() {
    try {
        const response = await fetch('/documents');
        const documents = await response.json();
        const docList = document.getElementById('docList');

        if (!response.ok) {
            window.location.href = '/login';
            return;
        }

        docList.innerHTML = '';
        documents.forEach(doc => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${doc.id}</td>
                <td>${doc.filename}</td>
                <td>${new Date(doc.upload_date).toLocaleString()}</td>
                <td>
                    <button class="download" onclick="downloadFile(${doc.id})">Download</button>
                    <button class="delete" onclick="deleteFile(${doc.id})">Delete</button>
                </td>
            `;
            docList.appendChild(row);
        });
        searchDocuments();
    } catch (error) {
        console.error('Error fetching all documents:', error);
        window.location.href = '/login';
    }
}

function downloadFile(docId) {
    window.location.href = `/download/${docId}`;
}

async function deleteFile(docId) {
    if (confirm('Are you sure you want to delete this file?')) {
        try {
            const response = await fetch(`/delete/${docId}`, {
                method: 'POST'
            });
            const result = await response.json();

            if (response.ok) {
                const sessionDocs = JSON.parse(sessionStorage.getItem('sessionDocs') || '[]');
                const updatedDocs = sessionDocs.filter(doc => doc.id !== docId);
                sessionStorage.setItem('sessionDocs', JSON.stringify(updatedDocs));
                if (window.location.pathname === '/user/documents') {
                    fetchAllDocuments();
                } else {
                    fetchDocuments();
                }
            } else {
                alert(`Error: ${result.error}`);
            }
        } catch (error) {
            alert(`Error: ${error.message}`);
        }
    }
}

function handleLogout() {
    const logoutLink = document.getElementById('logoutLink');
    logoutLink.addEventListener('click', async (e) => {
        e.preventDefault();
        await fetch('/auth/logout', { method: 'POST' });
        sessionStorage.removeItem('sessionDocs');
        window.location.href = '/login';
    });
}

function handleRequestCredits() {
    const button = document.getElementById('requestCredits');
    const messageEl = document.getElementById('requestMessage');

    button.addEventListener('click', async () => {
        try {
            const response = await fetch('/credits/request', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const result = await response.json();

            messageEl.textContent = response.ok ? result.message : result.error;
            messageEl.style.color = response.ok ? '#4CAF50' : '#F44336';
        } catch (error) {
            messageEl.textContent = `Error: ${error.message}`;
            messageEl.style.color = '#F44336';
        }
    });
}

function handleViewRequests() {
    const button = document.getElementById('viewRequests');
    const section = document.getElementById('requestsSection');

    if (button) {
        button.addEventListener('click', () => {
            section.style.display = section.style.display === 'none' ? 'block' : 'none';
        });
    }
}

function handleViewAnalytics() {
    const button = document.getElementById('viewAnalytics');
    if (button) {
        button.addEventListener('click', () => window.location.href = '/admin/analytics');
    }
}

async function updateCredits(requestId, action) {
    try {
        const response = await fetch('/admin/credits/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ request_id: requestId, action })
        });
        const result = await response.json();

        if (response.ok) location.reload();
        else alert(`Error: ${result.error}`);
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

function searchDocuments() {
    const search = document.getElementById('docSearch')?.value.toLowerCase() || '';
    const rows = document.getElementById('docList').getElementsByTagName('tr');
    Array.from(rows).forEach(row => {
        const filename = row.cells[1].textContent.toLowerCase();
        row.style.display = filename.includes(search) ? '' : 'none';
    });
}

function initializeFAB() {
    const fab = document.getElementById('fabUpload');
    fab.addEventListener('click', (e) => {
        e.preventDefault();
        const fileInput = document.getElementById('fileInput') || document.querySelector('input[type="file"]');
        if (fileInput) fileInput.scrollIntoView({ behavior: 'smooth' });
        else window.location.href = '/';
    });
}