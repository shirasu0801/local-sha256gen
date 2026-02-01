let authToken = '';

// ログイン画面
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = document.getElementById('masterPassword').value;
    const errorDiv = document.getElementById('loginError');
    
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            authToken = data.token;
            document.getElementById('loginScreen').classList.add('hidden');
            document.getElementById('mainScreen').classList.remove('hidden');
            document.getElementById('masterPassword').value = '';
            loadPasswords();
        } else {
            errorDiv.textContent = data.message || 'ログインに失敗しました';
        }
    } catch (error) {
        errorDiv.textContent = 'エラーが発生しました';
    }
});

// ログアウト
document.getElementById('logoutBtn').addEventListener('click', () => {
    authToken = '';
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('mainScreen').classList.add('hidden');
    document.getElementById('passwordList').innerHTML = '';
});

// パスワード追加
document.getElementById('addForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const entry = {
        service: document.getElementById('service').value,
        url: document.getElementById('url').value,
        user_id: document.getElementById('userId').value,
        password: document.getElementById('password').value
    };
    
    try {
        const response = await fetch('/api/passwords', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': authToken
            },
            body: JSON.stringify(entry)
        });
        
        if (response.ok) {
            document.getElementById('addForm').reset();
            loadPasswords();
        }
    } catch (error) {
        console.error('Error:', error);
    }
});

// パスワード生成
document.getElementById('generateBtn').addEventListener('click', async () => {
    try {
        const response = await fetch('/api/passwords/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': authToken
            },
            body: JSON.stringify({
                length: 16,
                use_upper: true,
                use_lower: true,
                use_numbers: true,
                use_symbols: false
            })
        });
        
        const data = await response.json();
        document.getElementById('password').value = data.password;
    } catch (error) {
        console.error('Error:', error);
    }
});

// パスワード一覧の読み込み
async function loadPasswords() {
    try {
        const response = await fetch('/api/passwords', {
            headers: { 'Authorization': authToken }
        });
        
        const passwords = await response.json();
        displayPasswords(passwords);
    } catch (error) {
        console.error('Error:', error);
    }
}

// パスワード一覧の表示
function displayPasswords(passwords) {
    const list = document.getElementById('passwordList');
    list.innerHTML = '';
    
    passwords.forEach(pwd => {
        const item = document.createElement('div');
        item.className = 'password-item';
        item.innerHTML = `
            <div class="password-item-info">
                <div class="password-item-label">サービス</div>
                <div class="password-item-value">${escapeHtml(pwd.service)}</div>
            </div>
            <div class="password-item-info">
                <div class="password-item-label">ユーザーID</div>
                <div class="password-item-value">${escapeHtml(pwd.user_id)}</div>
            </div>
            <div class="password-item-info">
                <div class="password-item-label">パスワード</div>
                <div class="password-item-value password-masked" id="pwd-${pwd.id}">••••••••</div>
            </div>
            <div class="password-item-actions">
                <button class="btn-copy" onclick="copyPassword('${pwd.id}')">コピー</button>
                <button class="btn-edit" onclick="togglePassword('${pwd.id}', '${escapeHtml(pwd.password)}')">表示</button>
                <button class="btn-delete" onclick="deletePassword('${pwd.id}')">削除</button>
            </div>
        `;
        list.appendChild(item);
    });
}

// パスワードの表示/非表示切り替え
let visiblePasswords = {};
function togglePassword(id, password) {
    const elem = document.getElementById(`pwd-${id}`);
    if (visiblePasswords[id]) {
        elem.textContent = '••••••••';
        elem.classList.add('password-masked');
        visiblePasswords[id] = false;
    } else {
        elem.textContent = password;
        elem.classList.remove('password-masked');
        visiblePasswords[id] = true;
    }
}

// パスワードをクリップボードにコピー
async function copyPassword(id) {
    try {
        const response = await fetch('/api/passwords', {
            headers: { 'Authorization': authToken }
        });
        const passwords = await response.json();
        const pwd = passwords.find(p => p.id === id);
        if (pwd) {
            await navigator.clipboard.writeText(pwd.password);
            alert('パスワードをコピーしました');
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

// パスワード削除
async function deletePassword(id) {
    if (!confirm('削除しますか？')) return;
    
    try {
        const response = await fetch(`/api/passwords?id=${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': authToken }
        });
        
        if (response.ok) {
            loadPasswords();
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

// HTMLエスケープ
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
