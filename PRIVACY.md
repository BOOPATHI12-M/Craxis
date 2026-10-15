# AI Phishing Guard Privacy Policy

Last updated: 2026-10-15

AI Phishing Guard checks the websites you visit for signs of phishing. This
document explains what it reads, where that data goes, and what is stored.

## What the extension reads

- **The address (URL) of each http or https page you open.** It is analysed by
  rules inside the extension.
- **The structure of the page.** The content script counts password fields,
  forms, links, iframes and scripts, and reads the page title, the site name
  meta tag and the icon address.
- **It never reads** what you type, form values, passwords, one-time codes,
  cookies, page text beyond the title, or your browsing history outside the
  pages you open.

## Where data goes

| Data | Destination | When |
| :--- | :--- | :--- |
| Page URL | The AI backend you configure. The default is `http://127.0.0.1:5000` on your own computer | Each scan, except for local addresses |
| Hostname | A public RDAP registry and the site itself | Only if you turn on domain age and certificate lookups in Settings **and** the backend is started with `AIPHISH_ENABLE_INTEL=1`. Off by default |
| Everything else | Nowhere. Page structure results stay in your browser | |

There is no analytics, no advertising, no remote logging and no account.
If you change the backend address to a remote server, the page URLs you visit
are sent to that server. Only do this for a server you control.

## What is stored

| Data | Where | Details |
| :--- | :--- | :--- |
| Scan history | `chrome.storage.local` on this device | Up to 100 entries: address, score, classification, reasons, time. Clear it on the History page |
| Settings and trusted sites | `chrome.storage.sync` | Backend address, thresholds, switches and your trusted-site list. If you are signed in to Chrome with sync turned on, the browser may sync these to your other devices |
| Current tab results and "proceed anyway" choices | `chrome.storage.session` | Removed when the browser closes |

## Permissions and why they are needed

| Permission | Reason |
| :--- | :--- |
| `http://*/*` and `https://*/*` | Run the page analysis on the sites you visit and call the backend |
| `scripting` | Inject the analysis script into pages that were open before the extension was installed |
| `storage` | Keep history, settings and tab results |
| `webNavigation` | Check an address before the page loads so dangerous pages can be blocked |

## Your controls

- Turn automatic scanning or blocking off in **Settings**.
- Add sites to the **trusted list**, or remove them, in Settings or the popup.
- Clear history on the **History** page.
- Remove the extension to delete all of its stored data.

## Limits

The extension gives an advisory risk estimate. It can be wrong in both
directions and is not a guarantee of safety.

## Contact

Open an issue in the project repository for questions about this policy.
