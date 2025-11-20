// convert-list.js
const fs = require('fs');
const path = require('path');

const DNR_RULE_ID_START = 1;
// Path relative to the extension root
const BLOCK_PAGE_URL = 'src/block_page/block_page.html';

console.log("Reading filter list...");
try {
    const text = fs.readFileSync('phishing-filter.txt', 'utf8');
    const domains = text.split('\n')
        .filter(line => line.trim().length > 0 && !line.startsWith('!'));

    console.log(`Found ${domains.length} domains. Converting to rules...`);

    const rules = domains.map((domain, index) => ({
        "id": DNR_RULE_ID_START + index,
        "priority": 1,
        "action": {
            "type": "redirect",
            "redirect": {
                "extensionPath": `/${BLOCK_PAGE_URL}?url=${encodeURIComponent(domain)}`
            }
        },
        "condition": {
            "urlFilter": "||" + domain + "^",
            "resourceTypes": ["main_frame"]
        }
    }));

    // Create a rulesets directory if it doesn't exist
    const rulesetDir = path.join(__dirname, 'rulesets');
    if (!fs.existsSync(rulesetDir)) {
        fs.mkdirSync(rulesetDir);
    }

    // Write the final JSON file
    const outputPath = path.join(rulesetDir, 'phishing_rules.json');
    fs.writeFileSync(outputPath, JSON.stringify(rules, null, 2));

    console.log(`Successfully created ${outputPath} with ${rules.length} rules.`);

} catch (err) {
    console.error("Error processing list:", err);
    process.exit(1); // Fail the action if something goes wrong
}