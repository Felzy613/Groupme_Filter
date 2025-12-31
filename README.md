# GroupMe Blocker

A desktop application to automatically block or allow specific GroupMe groups based on configurable rules.

## Features

- **Blacklist Mode**: Remove yourself from specified groups
- **Whitelist Mode**: Only stay in specified groups, remove from all others
- **Multi-Account Support**: Manage multiple GroupMe accounts
- **Global Blocklist**: Apply rules across all accounts
- **Auto-Removal**: Automatically leaves blocked groups
- **GUI Configuration**: Easy-to-use Tkinter interface

## ⚠️ Security

This application requires GroupMe API tokens to function. Tokens are **encrypted locally** using industry-standard encryption when stored.

### Setup Instructions

1. **Get your GroupMe API token**:
   - Go to [GroupMe Developer Portal](https://dev.groupme.com/)
   - Create an app or use an existing one
   - Your API token will be shown in the settings

2. **Install dependencies** (including encryption library):
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python GroupMe_Blocker.py
   ```

4. **Add accounts via the GUI**:
   - Click "Add" under the Accounts tab
   - Enter a label for the account
   - Paste your GroupMe API token when prompted
   - The token will be encrypted and stored securely

### Configuration & Security

Configuration is stored locally at:
- **macOS**: `~/Library/Application Support/GroupMeBlocker/accounts_config.json`
- **Encryption key**: `~/Library/Application Support/GroupMeBlocker/encryption.key`

#### How Tokens Are Secured

1. **Encrypted Storage**: When you add a token, it's encrypted using `cryptography.fernet` (AES encryption)
2. **Encryption Key**: A unique encryption key is generated and stored with restricted file permissions (owner read/write only)
3. **No Plaintext**: Tokens are NEVER stored in plaintext in the config file
4. **Automatic Decryption**: The app automatically decrypts tokens when needed

## Usage

1. Launch the application
2. Add a new account or select an existing one
3. Enter your GroupMe API token (via environment variable or direct input)
4. Select groups to block or allow
5. Choose your blocking mode (Blacklist or Whitelist)
6. The app will monitor your groups and automatically remove you from blocked ones

## Finding Group IDs to Block

1. Launch GroupMe Blocker
2. Add your account and enter your token
3. The app will automatically fetch all your groups
4. Click "Load Groups" to see all your groups with their IDs
5. Select the ones you want to block/allow
6. IDs will be displayed in the format: `123456789 | Group Name`

## Development

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python src/GroupMe_Blocker.py
```

## License

MIT
