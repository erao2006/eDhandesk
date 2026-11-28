import base64
import hashlib
import hmac
import json
import struct
import threading
import time
from datetime import datetime, timedelta, timezone

import requests
import streamlit as st

st.set_page_config(page_title="Live Desk", page_icon="📈", layout="centered",
                   initial_sidebar_state="collapsed")

BASE = "https://api.dhan.co/v2"
AUTH_URL = "https://auth.dhan.co/app/generateAccessToken"
UNDS = {"NIFTY": 13, "BANKNIFTY": 25, "SENSEX": 51, "FINNIFTY": 27, "MIDCPNIFTY": 442}

# Nifty 50 constituents -> Dhan NSE_EQ security IDs. Verify against Dhan's scrip master;
# the breadth card shows "N of 50" so a wrong or missing ID is visible.
NIFTY50 = {
    "RELIANCE": 2885, "TCS": 11536, "HDFCBANK": 1333, "ICICIBANK": 4963, "INFY": 1594,
    "BHARTIARTL": 10604, "SBIN": 3045, "ITC": 1660, "LT": 11483, "HINDUNILVR": 1394,
    "KOTAKBANK": 1922, "AXISBANK": 5900, "BAJFINANCE": 317, "MARUTI": 10999,
    "SUNPHARMA": 3351, "TITAN": 3506, "ASIANPAINT": 236, "ULTRACEMCO": 11532,
    "NTPC": 11630, "ONGC": 2475, "POWERGRID": 14977, "TATASTEEL": 3499, "WIPRO": 3787,
    "HCLTECH": 7229, "M&M": 2031, "ADANIPORTS": 15083, "ADANIENT": 25, "COALINDIA": 20374,
    "JSWSTEEL": 11723, "NESTLEIND": 17963, "BAJAJFINSV": 16675, "TECHM": 13538,
    "GRASIM": 1232, "HINDALCO": 1363, "CIPLA": 694, "DRREDDY": 881, "EICHERMOT": 910,
    "APOLLOHOSP": 157, "SBILIFE": 21808, "HDFCLIFE": 467, "TATACONSUM": 3432,
    "BAJAJ-AUTO": 16669, "SHRIRAMFIN": 4306, "TRENT": 1964, "BEL": 383, "ETERNAL": 5097,
    "JIOFIN": 18143, "TATAMOTORS": 3456, "INDUSINDBK": 5258,
}

# Approximate Nifty 50 weights (%). Update from NSE's monthly index factsheet.
HEAVY = {"HDFCBANK": 12.9, "ICICIBANK": 9.0, "RELIANCE": 8.1, "INFY": 4.9,
         "BHARTIARTL": 4.7, "LT": 4.0, "ITC": 3.5, "TCS": 3.4}

st.markdown("""
<style>
.block-container{padding-top:1.2rem;padding-bottom:3rem;max-width:560px}
.oc{width:100%;border-collapse:collapse;font-size:13px;font-variant-numeric:tabular-nums}
.oc th{font-weight:600;opacity:.6;font-size:11px;padding:4px 3px;text-align:right}
.oc td{padding:7px 4px;text-align:right;border-top:1px solid rgba(128,128,128,.25);white-space:nowrap}
.oc td.k{text-align:center;font-weight:700;background:rgba(128,128,128,.12)}
.oc tr.atm td.k{background:#2457d6;color:#fff}
.up{color:#1aa56a}.dn{color:#e0524f}
.pos{display:flex;justify-content:space-between;padding:8px 0;border-top:1px solid rgba(128,128,128,.25)}
.pos small{opacity:.6}
div[data-testid="stHorizontalBlock"]{flex-wrap:nowrap!important;gap:.5rem!important}
div[data-testid="stHorizontalBlock"]>div[data-testid="stColumn"],
div[data-testid="stHorizontalBlock"]>div[data-testid="column"]{min-width:0!important;flex:1 1 0!important;width:auto!important}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------- password gate
def gate():
    pw = st.secrets.get("APP_PASSWORD", "")
    if not pw or st.session_state.get("ok"):
        return
    entered = st.text_input("Password", type="password")
    if entered and hmac.compare_digest(entered, str(pw)):
        st.session_state["ok"] = True
        st.rerun()
    elif entered:
        st.error("Wrong password.")
    st.stop()


gate()


# ---------------------------------------------------------------- token management
@st.cache_resource
def _store():
    return {"token": str(st.secrets.get("DHAN_ACCESS_TOKEN", "")).strip(), "lock": threading.Lock(),
            "err": "", "renew_after": 0, "gen_after": 0}


RENEW_BELOW = 2 * 3600      # only try to renew in the last 2 hours of the 24h token
RENEW_COOLDOWN = 15 * 60    # after a failed renew, don't try again for 15 min
GEN_COOLDOWN = 150          # never attempt a login (TOTP) more than once per 2.5 min


def _jwt_exp(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))["exp"]
    except Exception:
        return 0


def _totp(secret):
    key = base64.b32decode(secret.replace(" ", "").upper() + "=" * (-len(secret.replace(" ", "")) % 8))
    h = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 10**6:06d}"


def _cid():
    return str(st.secrets.get("DHAN_CLIENT_ID", "")).strip()


def _renew(tok):
    r = requests.get(f"{BASE}/RenewToken", headers={"access-token": tok, "dhanClientId": _cid()}, timeout=15)
    j = r.json()
    new = j.get("accessToken") or j.get("access_token")
    if not r.ok or not new:
        raise RuntimeError(j.get("errorMessage") or j.get("message") or "Renew refused")
    return new


def _generate():
    pin, secret = str(st.secrets.get("PIN", "")), str(st.secrets.get("TOTP_SECRET", ""))
    if not pin or not secret:
        raise RuntimeError("Token expired. Update ACCESS_TOKEN in Secrets, or add PIN and TOTP_SECRET for automatic login.")
    r = requests.post(AUTH_URL, params={"dhanClientId": _cid(), "pin": pin, "totp": _totp(secret)}, timeout=15)
    j = r.json()
    if not r.ok or not j.get("accessToken"):
        raise RuntimeError(j.get("message") or j.get("errorMessage") or "Automatic login failed")
    return j["accessToken"]


def token(force=False, bad=None):
    """Return a usable token. `bad` is the token the server just rejected (401)."""
    s = _store()
    with s["lock"]:
        now = time.time()
        tok = s["token"]
        # Another call already replaced the rejected token: just use the new one.
        if force and bad and tok != bad:
            return tok
        left = _jwt_exp(tok) - now
        valid = bool(tok) and left > 0
        have_login = bool(st.secrets.get("PIN") and st.secrets.get("TOTP_SECRET"))

        # Near expiry: one renew attempt, then a cooldown (success or failure).
        if valid and not force and left < RENEW_BELOW and now >= s["renew_after"]:
            s["renew_after"] = now + RENEW_COOLDOWN
            try:
                s["token"] = _renew(tok)
                s["renew_after"] = 0
                s["err"] = ""
                return s["token"]
            except Exception as e:
                s["err"] = f"Renew failed: {e}"

        # Expired or rejected by the server: log in, rate-limited.
        if (not valid or force) and have_login:
            if now < s["gen_after"]:
                raise RuntimeError(s["err"] or "Auto-login on cooldown, retrying shortly")
            s["gen_after"] = now + GEN_COOLDOWN
            try:
                s["token"] = _generate()
                s["err"] = ""
                return s["token"]
            except Exception as e:
                s["err"] = f"Auto-login failed: {e}"
                raise

        if not valid:
            raise RuntimeError("Token expired. Update ACCESS_TOKEN in Secrets, or add PIN and TOTP_SECRET.")
        return tok


# ---------------------------------------------------------------- API
def api(path, body=None, _retry=True):
    tok = token()
    headers = {"access-token": tok, "client-id": _cid(), "Accept": "application/json"}
    if body is None:
        r = requests.get(BASE + path, headers=headers, timeout=15)
    else:
        headers["Content-Type"] = "application/json"
        r = requests.post(BASE + path, headers=headers, json=body, timeout=15)
    try:
        j = r.json()
    except Exception:
        j = {}
    failed = (not r.ok) or (isinstance(j, dict) and (j.get("errorCode") or j.get("status") == "failed"))
    if failed:
        if _retry and (r.status_code == 401 or (isinstance(j, dict) and j.get("errorCode") in ("DH-901", "DH-902"))):
            token(force=True, bad=tok)
            return api(path, body, _retry=False)
        msg = (isinstance(j, dict) and (j.get("errorMessage") or j.get("message"))) or f"Request failed ({r.status_code})"
        raise RuntimeError(msg)
    return j


def expiries(und):
    """Expiry list per index, kept for an hour. After a failure (for example Dhan's
    rate limit) it waits 30 seconds before trying again instead of retrying on every rerun."""
    cache = st.session_state.setdefault("_exp", {})
    ent = cache.get(und)
    now = time.time()
    if ent and ent["list"] and now - ent["t"] < 3600:
        return ent["list"]
    if ent and ent.get("fail") and now - ent["fail"] < 30:
        if ent["list"]:
            return ent["list"]
        raise RuntimeError(ent["msg"] + " (waiting before retry; tap Refresh now)")
    try:
        j = api("/optionchain/expirylist", {"UnderlyingScrip": UNDS[und], "UnderlyingSeg": "IDX_I"})
        lst = sorted(j.get("data", []))
        cache[und] = {"list": lst, "t": now}
        return lst
    except Exception as e:
        cache[und] = {"list": ent["list"] if ent else [], "t": ent["t"] if ent else 0,
                      "fail": now, "msg": str(e)}
        raise


@st.cache_data(ttl=5, show_spinner=False)
def chain(und, expiry):
    return api("/optionchain", {"UnderlyingScrip": UNDS[und], "UnderlyingSeg": "IDX_I", "Expiry": expiry})


@st.cache_data(ttl=5, show_spinner=False)
def quotes():
    # One call for Nifty 50 stocks (breadth) and the three indices (header row)
    return api("/marketfeed/quote", {"NSE_EQ": list(NIFTY50.values()), "IDX_I": [13, 25, 51]})


@st.cache_data(ttl=900, show_spinner=False)
def prev_day(sec_id, day):
    """Previous trading day's High/Low/Close from Dhan daily candles. `day` (today, IST) only keys the cache.
    Returns (data, error); a failure is cached for 15 min so the 10s refresh doesn't hammer the API."""
    try:
        end = datetime.strptime(day, "%Y-%m-%d")
        j = api("/charts/historical", {
            "securityId": str(sec_id), "exchangeSegment": "IDX_I", "instrument": "INDEX",
            "expiryCode": 0, "oi": False,
            "fromDate": (end - timedelta(days=12)).strftime("%Y-%m-%d"),
            "toDate": (end + timedelta(days=1)).strftime("%Y-%m-%d")})
        hi, lo, cl, ts = j.get("high") or [], j.get("low") or [], j.get("close") or [], j.get("timestamp") or []
        ist = timezone(timedelta(hours=5, minutes=30))
        for i in range(len(cl) - 1, -1, -1):
            t = ts[i] + (315532800 if ts[i] < 1.6e9 else 0)   # some Dhan responses count from 1980
            if datetime.fromtimestamp(t, ist).strftime("%Y-%m-%d") < day:
                return {"h": hi[i], "l": lo[i], "c": cl[i], "d": datetime.fromtimestamp(t, ist).strftime("%d %b")}, ""
        return None, "No earlier daily candle returned."
    except Exception as e:
        return None, str(e)


def pivots(h, l, c):
    p = (h + l + c) / 3
    return {"R2": p + (h - l), "R1": 2 * p - l, "Pivot": p, "S1": 2 * p - h, "S2": p - (h - l)}


# ---------------------------------------------------------------- formatting
def inr(n, d=2):
    return f"{n:,.{d}f}"


def lakh(n):
    a = abs(n)
    if a >= 1e7:
        return f"{n / 1e7:.2f} Cr"
    if a >= 1e5:
        return f"{n / 1e5:.1f} L"
    if a >= 1e3:
        return f"{n / 1e3:.1f} K"
    return f"{int(n)}"


def cls(n):
    return "up" if n > 0 else "dn" if n < 0 else ""


# ---------------------------------------------------------------- controls (outside the refreshing block)
st.title("Live Desk")
row1 = st.columns([1.1, 1.3, 0.9])      # Index | Expiry | Centre strike, side by side
row2 = st.columns(2)                    # Refresh | Auto-refresh
if row2[0].button("↻ Refresh", use_container_width=True):
    quotes.clear()
    chain.clear()
    st.session_state.get("_exp", {}).pop(st.session_state.get("und", "NIFTY"), None)
auto = row2[1].toggle("Auto 10s", value=False)
und = row1[0].selectbox("Index", list(UNDS), key="und")
try:
    exp_list = expiries(und)
except Exception as e:
    exp_list = []
    st.warning(f"Expiries: {e}")
expiry = row1[1].selectbox("Expiry", exp_list, key="expiry") if exp_list else None
centre = row1[2].number_input("Centre", min_value=0, value=0, step=50, key="centre",
                              help="Centre strike. 0 = automatic (at the money)")


# ---------------------------------------------------------------- live block
def desk():
    ist = datetime.now(timezone(timedelta(hours=5, minutes=30)))
    st.caption(f"Updated {ist:%H:%M:%S} IST" + (" · auto-refresh on" if auto else " · tap Refresh now to update"))

    # Index strip: Nifty 50, Bank Nifty, Sensex in one row
    try:
        qi = (quotes().get("data") or {}).get("IDX_I", {})
        th = "<th style='text-align:center'>{}</th>"
        td = "<td style='text-align:center'><b>{}</b><br><span class='{}'>{}</span></td>"
        heads, cells = "", ""
        for name, sid in (("NIFTY 50", 13), ("BANK NIFTY", 25), ("SENSEX", 51)):
            x = qi.get(str(sid)) or {}
            ltp = x.get("last_price") or 0
            pc = (x.get("ohlc") or {}).get("close") or 0
            chg = (ltp - pc) if (ltp and pc) else (x.get("net_change") or 0)
            pct = f" ({chg / pc * 100:+.2f}%)" if pc else ""
            heads += th.format(name)
            cells += td.format(inr(ltp), cls(chg), f"{chg:+,.2f}{pct}")
        st.markdown(f"<table class='oc'><tr>{heads}</tr><tr>{cells}</tr></table>", unsafe_allow_html=True)
    except Exception as e:
        st.warning(f"Indices: {e}")

    # Breadth
    st.subheader("Nifty 50 breadth")
    try:
        q = (quotes().get("data") or {}).get("NSE_EQ", {})
        a = d = u = 0
        for x in q.values():
            ltp, pc = x.get("last_price") or 0, (x.get("ohlc") or {}).get("close") or 0
            if not ltp or not pc:
                continue
            a, d, u = (a + 1, d, u) if ltp > pc else (a, d + 1, u) if ltp < pc else (a, d, u + 1)
        n = a + d + u
        ratio = f"{a / d:.2f}" if d else ("∞" if a else "–")
        st.markdown(
            "<table class='oc'><tr><th style='text-align:center'>Adv</th><th style='text-align:center'>Dec</th>"
            "<th style='text-align:center'>Unch</th><th style='text-align:center'>A/D</th></tr>"
            f"<tr><td class='up' style='text-align:center;font-weight:700'>{a}</td>"
            f"<td class='dn' style='text-align:center;font-weight:700'>{d}</td>"
            f"<td style='text-align:center;font-weight:700'>{u}</td>"
            f"<td style='text-align:center;font-weight:700'>{ratio}</td></tr></table>",
            unsafe_allow_html=True)
        st.caption(f"{n} of {len(NIFTY50)} stocks priced" + ("" if n == len(NIFTY50) else " · check security IDs in app.py"))
    except Exception as e:
        st.warning(f"Breadth: {e}")

    # Heavyweights
    st.subheader("Top 8 heavyweights")
    try:
        q = (quotes().get("data") or {}).get("NSE_EQ", {})
        rows, wsum, wmove = [], 0.0, 0.0
        for sym, w in HEAVY.items():
            x = q.get(str(NIFTY50[sym])) or {}
            ltp = x.get("last_price") or 0
            pc = (x.get("ohlc") or {}).get("close") or 0
            pct = (ltp - pc) / pc * 100 if (ltp and pc) else 0
            if ltp and pc:
                wsum += w
                wmove += w * pct
            rows.append(f"<tr><td style='text-align:left'><b>{sym}</b></td><td>{w:.1f}%</td>"
                        f"<td>{inr(ltp) if ltp else '–'}</td>"
                        f"<td class='{cls(pct)}'>{pct:+.2f}%</td></tr>")
        st.markdown("<table class='oc'><tr><th style='text-align:left'>Stock</th><th>Wt</th><th>LTP</th><th>Chg</th></tr>"
                    + "".join(rows) + "</table>", unsafe_allow_html=True)
        if wsum:
            st.caption(f"Weighted move of these stocks: {wmove / wsum:+.2f}%  ·  weights are approximate")
    except Exception as e:
        st.warning(f"Heavyweights: {e}")

    # Pivot levels (classic) for the selected index
    st.subheader(f"Pivot levels · {und}")
    try:
        today = datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime("%Y-%m-%d")
        pd_, err = prev_day(UNDS[und], today)
        if not pd_:
            raise RuntimeError(err or "No data")
        lv = pivots(pd_["h"], pd_["l"], pd_["c"])
        x = ((quotes().get("data") or {}).get("IDX_I", {})).get(str(UNDS[und])) or {}
        ltp = x.get("last_price") or 0
        near = min(lv, key=lambda k: abs(lv[k] - ltp)) if ltp else None
        rows = []
        for name, v in lv.items():
            c_ = "up" if name.startswith("S") else "dn" if name.startswith("R") else ""
            dist = f"{(v - ltp) / ltp * 100:+.2f}%" if ltp else "–"
            rows.append(f"<tr class='{'atm' if name == near else ''}'><td class='k'>{name}</td>"
                        f"<td class='{c_}'><b>{inr(v)}</b></td><td>{dist}</td></tr>")
        st.markdown("<table class='oc'><tr><th style='text-align:center'>Level</th><th>Price</th><th>From LTP</th></tr>"
                    + "".join(rows) + "</table>", unsafe_allow_html=True)
        st.caption(f"From {pd_['d']}: H {inr(pd_['h'])} · L {inr(pd_['l'])} · C {inr(pd_['c'])}"
                   + (f"  ·  LTP {inr(ltp)}" if ltp else ""))
    except Exception as e:
        st.warning(f"Pivots: {e}")

    # OI
    st.subheader("Open interest · 5 strikes each side")
    try:
        if not expiry:
            raise RuntimeError("No expiry available.")
        d_ = chain(und, expiry).get("data", {})
        oc, spot = d_.get("oc", {}), float(d_.get("last_price") or 0)
        strikes = sorted(float(k) for k in oc)
        if not strikes:
            raise RuntimeError("No option chain returned.")
        want = float(centre) if centre else spot
        ci = min(range(len(strikes)), key=lambda i: abs(strikes[i] - want))
        sel = strikes[max(0, ci - 5): ci + 6]
        keymap = {float(k): k for k in oc}
        rows, mx, sc, sp = [], 1, 0, 0
        for s in sel:
            e = oc[keymap[s]]
            ce, pe = e.get("ce") or {}, e.get("pe") or {}
            r = (s, ce.get("oi") or 0, (ce.get("oi") or 0) - (ce.get("previous_oi") or 0),
                 pe.get("oi") or 0, (pe.get("oi") or 0) - (pe.get("previous_oi") or 0))
            rows.append(r)
            mx = max(mx, r[1], r[3])
            sc += r[1]
            sp += r[3]
        html = ["<table class='oc'><tr><th>Call OI</th><th>Chg</th><th style='text-align:center'>Strike</th><th>Chg</th><th>Put OI</th></tr>"]
        for s, co, cc, po, pc_ in rows:
            cp, pp = co / mx * 100, po / mx * 100
            html.append(
                f"<tr class='{'atm' if s == strikes[ci] else ''}'>"
                f"<td style='background:linear-gradient(to left,rgba(224,82,79,.28) {cp:.0f}%,transparent {cp:.0f}%)'>{lakh(co)}</td>"
                f"<td class='{cls(cc)}'>{'+' if cc > 0 else ''}{lakh(cc)}</td>"
                f"<td class='k'>{int(s)}</td>"
                f"<td class='{cls(pc_)}'>{'+' if pc_ > 0 else ''}{lakh(pc_)}</td>"
                f"<td style='background:linear-gradient(to right,rgba(26,165,106,.28) {pp:.0f}%,transparent {pp:.0f}%)'>{lakh(po)}</td></tr>")
        html.append("</table>")
        st.markdown("".join(html), unsafe_allow_html=True)
        st.caption(f"Spot {inr(spot)}  ·  Put/Call ratio for these strikes {sp / sc:.2f}" if sc else f"Spot {inr(spot)}")
    except Exception as e:
        st.warning(f"Option chain: {e}")

    # Funds
    try:
        f = api("/fundlimit")
        st.metric("Funds available", f"₹ {inr(f.get('availabelBalance', f.get('availableBalance', 0)))}")
        st.caption(f"Used ₹ {inr(f.get('utilizedAmount', 0))}  ·  Withdrawable ₹ {inr(f.get('withdrawableBalance', 0))}")
    except Exception as e:
        st.warning(f"Funds: {e}")

    # Positions
    st.subheader("Positions")
    try:
        pos = api("/positions")
        pos = pos if isinstance(pos, list) else []
        total = sum((p.get("realizedProfit") or 0) + (p.get("unrealizedProfit") or 0) for p in pos)
        if pos:
            st.markdown(f"Day P&L: <b class='{cls(total)}'>₹ {inr(total)}</b>", unsafe_allow_html=True)
            rows = []
            for p in sorted(pos, key=lambda x: x.get("netQty", 0) == 0):
                q = p.get("netQty", 0)
                pl = (p.get("realizedProfit") or 0) + (p.get("unrealizedProfit") or 0)
                avg = p.get("buyAvg") if q > 0 else p.get("sellAvg")
                state = "Closed" if q == 0 else f"{'Long' if q > 0 else 'Short'} {abs(q)} @ {inr(avg or 0)}"
                rows.append(f"<div class='pos'><div><b>{p.get('tradingSymbol', p.get('securityId'))}</b><br>"
                            f"<small>{state}</small></div><b class='{cls(pl)}'>{'+' if pl > 0 else ''}{inr(pl)}</b></div>")
            st.markdown("".join(rows), unsafe_allow_html=True)
        else:
            st.caption("No positions today.")
    except Exception as e:
        st.warning(f"Positions: {e}")

if not _cid():
    st.error("Add CLIENT_ID and ACCESS_TOKEN in the app's Secrets (see secrets.toml.example).")
else:
    st.fragment(run_every=10 if auto else None)(desk)()