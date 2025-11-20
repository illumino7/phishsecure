// src/background.js
const PHISHING_RULESET_ID = "phishing_ruleset";
let isEnabled = true;

// 1. Lifecycle & Initialization
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({ isEnabled: true }, () => {
        loadStateAndApply();
    });
});

chrome.runtime.onStartup.addListener(() => {
    loadStateAndApply();
});

// 2. Message Handling
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.command === 'updateState') {
        loadStateAndApply();
    } else if (message.command === 'whitelistTemporarily') {
        // Async action requires return true
        addTemporaryAllowRule(message.url)
            .then(() => sendResponse({ success: true }));
        return true;
    }
});

// 3. State Logic
async function loadStateAndApply() {
    const { isEnabled: storedIsEnabled } = await chrome.storage.local.get('isEnabled');
    isEnabled = storedIsEnabled !== false;

    console.log(`State Loaded: Enabled: ${isEnabled}`);
    applyBlockingMode();
}

async function applyBlockingMode() {
    if (!isEnabled) {
        console.log("Protection is OFF.");
        await chrome.declarativeNetRequest.updateEnabledRulesets({
            disableRulesetIds: [PHISHING_RULESET_ID]
        });
        return;
    }

    if (isEnabled) {
        console.log("Applying PHISHING mode.");
        await chrome.declarativeNetRequest.updateEnabledRulesets({
            enableRulesetIds: [PHISHING_RULESET_ID]
        });
    }
}

// 4. Proceed Button Logic
async function addTemporaryAllowRule(domain) {
    const sessionRules = await chrome.declarativeNetRequest.getSessionRules();
    // Calculate next ID safely (defaults to 1 if no rules exist)
    const nextId = sessionRules.length > 0
        ? Math.max(...sessionRules.map(r => r.id)) + 1
        : 1;

    const urlFilter = "||" + domain + "^";

    await chrome.declarativeNetRequest.updateSessionRules({
        addRules: [{
            "id": nextId,
            "priority": 2,
            "action": { "type": "allow" },
            "condition": {
                "urlFilter": urlFilter,
                "resourceTypes": ["main_frame"]
            }
        }]
    });

    // TYPO FIXED HERE: Changed NextId -> nextId
    console.log(`Temporarily allowed domain: ${domain} with rule ID ${nextId}`);
}