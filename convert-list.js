const fs = require("fs");
const path = require("path");

// --- Configuration ---
const DNR_RULE_ID_START = 1;
const BLOCK_PAGE_URL = "src/block_page/block_page.html";
const PHISHING_FILTER_PATH = "phishing-filter.txt";
const RULESETS_DIR = path.join(__dirname, "rulesets");
const BASE_RULES_PATH = path.join(RULESETS_DIR, "phishing_rules.json");
const PATCH_RULES_PATH = path.join(RULESETS_DIR, "updates.json");

// Get arguments
const isReleaseMode = process.argv.includes("--release");

// Ensure directories exist
if (!fs.existsSync(RULESETS_DIR)) fs.mkdirSync(RULESETS_DIR);

// --- 1. NEW: The Cleaning Logic ---
function cleanLine(line) {
    let clean = line.trim();

    // Remove options like $all, $document, etc.
    if (clean.includes("$")) {
        clean = clean.split("$")[0];
    }

    // Remove the trailing separator '^' if present
    if (clean.endsWith("^")) {
        clean = clean.slice(0, -1);
    }

    // Remove the leading anchor '||' if present
    if (clean.startsWith("||")) {
        clean = clean.substring(2);
    }

    return clean;
}

// --- Helper: Parse Raw Text List ---
function parseRawList(filePath) {
    if (!fs.existsSync(filePath)) return new Set();
    const text = fs.readFileSync(filePath, "utf8");

    const validLines = new Set();

    text.split("\n").forEach((line) => {
        const trimmed = line.trim();
        // Skip comments and empty lines
        if (!trimmed || trimmed.startsWith("!")) return;

        // CLEAN the line (Turn "||vk.cc/abc^$all" into "vk.cc/abc")
        const cleaned = cleanLine(trimmed);

        if (cleaned.length > 0) {
            validLines.add(cleaned);
        }
    });

    return validLines;
}

// --- Helper: Parse Existing JSON Ruleset ---
function parseBaseJson(filePath) {
    if (!fs.existsSync(filePath)) return new Set();
    try {
        const rules = JSON.parse(fs.readFileSync(filePath, "utf8"));
        // Extract raw domain/path back from "||domain.com^"
        const domains = rules.map((r) => {
            let filter = r.condition.urlFilter;
            // Reverse the DNR wrapping
            if (filter.startsWith("||")) filter = filter.substring(2);
            if (filter.endsWith("^")) filter = filter.slice(0, -1);
            return filter;
        });
        return new Set(domains);
    } catch (e) {
        return new Set();
    }
}

// --- Helper: Generate Rule Objects ---
function generateRules(domains, startId = 1) {
    return Array.from(domains).map((domain, index) => ({
        id: startId + index,
        priority: 1,
        action: {
            type: "redirect",
            redirect: {
                extensionPath: `/${BLOCK_PAGE_URL}?url=${encodeURIComponent(domain)}`,
            },
        },
        condition: {
            // Now we safely re-wrap it in DNR syntax
            urlFilter: "||" + domain + "^",
            resourceTypes: ["main_frame"],
        },
    }));
}

// --- MAIN LOGIC ---

console.log(`Running in ${isReleaseMode ? "RELEASE" : "PATCH"} mode...`);

const newDomainsSet = parseRawList(PHISHING_FILTER_PATH);
console.log(`Fresh list contains ${newDomainsSet.size} unique rules.`);

if (isReleaseMode) {
    // RELEASE MODE
    const allRules = generateRules(newDomainsSet, DNR_RULE_ID_START);
    fs.writeFileSync(BASE_RULES_PATH, JSON.stringify(allRules, null, 2));
    fs.writeFileSync(PATCH_RULES_PATH, "[]"); // Clear patch

    console.log(`[RELEASE] Updated Base with ${allRules.length} rules.`);
} else {
    // PATCH MODE
    const currentBaseSet = parseBaseJson(BASE_RULES_PATH);

    const patchDomains = [];
    for (const domain of newDomainsSet) {
        if (!currentBaseSet.has(domain)) {
            patchDomains.push(domain);
        }
    }

    // Safety Check: 5,000 Rule Limit
    if (patchDomains.length > 5000) {
        console.error(
            `[CRITICAL] Patch size (${patchDomains.length}) exceeds Chrome limit (5000).`,
        );
        console.error(
            `[ACTION REQUIRED] Run the '[MANUAL] Full Release Update' workflow.`,
        );
        process.exit(1);
    }

    const patchRules = generateRules(patchDomains, DNR_RULE_ID_START);
    fs.writeFileSync(PATCH_RULES_PATH, JSON.stringify(patchRules, null, 2));

    console.log(
        `[PATCH] Generated updates.json with ${patchRules.length} new rules.`,
    );
}
