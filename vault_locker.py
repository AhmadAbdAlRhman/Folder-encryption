"""
Vault Locker - lock whole folders into a single AES-256-GCM encrypted .vault file.

Install:  pip install customtkinter cryptography pyinstaller
Run:      python vault_locker.py
Build:    pyinstaller --noconfirm --onefile --windowed --collect-all customtkinter --name "Vault Locker" vault_locker.py

Vault format (v2)
  header : b"AESV2" | log2(N) (1 byte) | salt (16) | nonce prefix (8)
  body   : repeated  [ 4-byte big-endian length | AES-GCM ciphertext+tag ]  (1 MiB chunks)
  nonce  : prefix + 4-byte chunk counter
  AAD    : header + 0x01 for the last chunk / 0x00 otherwise (detects truncation & reordering)
  key    : scrypt(password NFKC, salt, N=2^17, r=8, p=1) -> 32 bytes
"""
import os
import stat
import sys
import shutil
import struct
import tempfile
import threading
import subprocess
import unicodedata
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

APP_NAME = "Vault Locker"
MAGIC = b"AESV2"
EXT = ".vault"
SALT_LEN = 16
PREFIX_LEN = 8
CHUNK = 1024 * 1024
SCRYPT_LOG2N = 17
SCRYPT_R = 8
SCRYPT_P = 1
HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + PREFIX_LEN


# ============================ CORE (no GUI) ============================

class VaultError(Exception):
    pass


class WrongPassword(VaultError):
    pass


def derive_key(password: str, salt: bytes, log2n: int) -> bytes:
    pw = unicodedata.normalize("NFKC", password).encode("utf-8")
    return Scrypt(salt=salt, length=32, n=2 ** log2n, r=SCRYPT_R, p=SCRYPT_P).derive(pw)


def _nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + counter.to_bytes(4, "big")


def encrypt_file(src, dst, password, progress=None):
    """Encrypt src -> dst atomically (writes dst.tmp then replaces)."""
    salt, prefix = os.urandom(SALT_LEN), os.urandom(PREFIX_LEN)
    header = MAGIC + bytes([SCRYPT_LOG2N]) + salt + prefix
    aes = AESGCM(derive_key(password, salt, SCRYPT_LOG2N))
    total = max(os.path.getsize(src), 1)
    done, counter = 0, 0
    tmp = dst + ".tmp"
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(header)
            cur = fin.read(CHUNK)
            while True:
                nxt = fin.read(CHUNK)
                last = not nxt
                ct = aes.encrypt(_nonce(prefix, counter), cur,
                                 header + (b"\x01" if last else b"\x00"))
                fout.write(struct.pack(">I", len(ct)))
                fout.write(ct)
                counter += 1
                done += len(cur)
                if progress:
                    progress(min(done / total, 1.0))
                if last:
                    break
                cur = nxt
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp, dst)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def decrypt_stream(src, password, progress=None):
    """Yield plaintext chunks. Raises WrongPassword / VaultError."""
    size = os.path.getsize(src)
    with open(src, "rb") as f:
        header = f.read(HEADER_LEN)
        if len(header) < HEADER_LEN or not header.startswith(MAGIC):
            raise VaultError("This is not a valid vault file.")
        log2n = header[len(MAGIC)]
        if not 10 <= log2n <= 20:
            raise VaultError("Unsupported vault parameters.")
        off = len(MAGIC) + 1
        salt = header[off:off + SALT_LEN]
        prefix = header[off + SALT_LEN:]
        aes = AESGCM(derive_key(password, salt, log2n))
        counter = 0
        while True:
            raw = f.read(4)
            if len(raw) < 4:
                raise VaultError("The vault file is truncated.")
            (n,) = struct.unpack(">I", raw)
            if n < 16 or n > CHUNK + 16:
                raise VaultError("The vault file is corrupted.")
            ct = f.read(n)
            if len(ct) < n:
                raise VaultError("The vault file is truncated.")
            last = f.tell() >= size
            try:
                pt = aes.decrypt(_nonce(prefix, counter), ct,
                                 header + (b"\x01" if last else b"\x00"))
            except InvalidTag:
                if counter == 0:
                    raise WrongPassword()
                raise VaultError("The vault is corrupted, truncated or has been modified.")
            counter += 1
            if progress:
                progress(min(f.tell() / size, 1.0))
            yield pt
            if last:
                break


def decrypt_to_file(src, dst, password, progress=None):
    with open(dst, "wb") as out:
        for chunk in decrypt_stream(src, password, progress):
            out.write(chunk)


def verify_vault(src, password, progress=None):
    for _ in decrypt_stream(src, password, progress):
        pass


def zip_folder(folder, zip_path, progress=None):
    files, dirs, total = [], [], 0
    for root, dnames, fnames in os.walk(folder):
        dirs += [os.path.join(root, d) for d in dnames]
        for fn in fnames:
            p = os.path.join(root, fn)
            files.append(p)
            try:
                total += os.path.getsize(p)
            except OSError:
                pass
    total, done = max(total, 1), 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for d in dirs:
            z.write(d, os.path.relpath(d, folder))
        for p in files:
            try:
                z.write(p, os.path.relpath(p, folder))
            except OSError as e:
                raise VaultError(f"Cannot read '{p}'. Is it open in another program?\n({e.strerror or e})") from e
            try:
                done += os.path.getsize(p)
            except OSError:
                pass
            if progress:
                progress(min(done / total, 1.0))


def unzip_to(zip_path, dest, progress=None):
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        members = z.infolist()
        total, done = max(sum(m.file_size for m in members), 1), 0
        for m in members:
            z.extract(m, dest)
            done += m.file_size
            if progress:
                progress(min(done / total, 1.0))


def wipe_dir(path) -> bool:
    """Delete a directory tree (also read-only files). Returns True if gone."""
    def fix(func, p, *_):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=fix)
    else:
        shutil.rmtree(path, onerror=fix)
    return not os.path.exists(path)


def remove_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass


def is_inside(child, parent) -> bool:
    child, parent = os.path.abspath(child), os.path.abspath(parent)
    try:
        return os.path.commonpath([child, parent]) == parent
    except ValueError:
        return False


def password_strength(pw: str):
    """Return (score 0..4, label, color)."""
    if len(pw) < 8:
        return (1 if pw else 0), ("Too short" if pw else ""), "#E5484D"
    classes = sum([any(c.islower() for c in pw), any(c.isupper() for c in pw),
                   any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)])
    score = 1 + (len(pw) >= 12) + (len(pw) >= 16) + (classes >= 3)
    score = min(score, 4)
    return score, {1: "Weak", 2: "Fair", 3: "Good", 4: "Strong"}[score], \
        {1: "#E5484D", 2: "#F5A524", 3: "#3E9BFF", 4: "#30A46C"}[score]


def open_in_file_manager(path):
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


# ============================ GUI ============================
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

MUTED = ("gray35", "gray65")
CARD = ("gray90", "gray17")
GREEN = ("#2FA36B", "#2FA36B")
RED = ("#D5484D", "#D5484D")


class Task:
    """Runs fn(task) in a thread; the UI polls progress/status/done."""

    def __init__(self, fn):
        self.progress, self.status = 0.0, ""
        self.result, self.error, self.done = None, None, False
        self._fn = fn
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            self.result = self._fn(self)
        except BaseException as e:  # noqa
            self.error = e
        finally:
            self.done = True

    def sub(self, lo, hi):
        return lambda p: setattr(self, "progress", lo + (hi - lo) * p)


def page_header(parent, title, subtitle):
    ctk.CTkLabel(parent, text=title, font=ctk.CTkFont(size=26, weight="bold"), anchor="w").pack(fill="x")
    ctk.CTkLabel(parent, text=subtitle, font=ctk.CTkFont(size=13), text_color=MUTED,
                 anchor="w", justify="left").pack(fill="x", pady=(2, 0))


def field_label(parent, text):
    ctk.CTkLabel(parent, text=text, anchor="w",
                 font=ctk.CTkFont(size=13, weight="bold")).pack(fill="x", padx=22, pady=(16, 5))


def path_row(parent, var, button_text, command):
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", padx=22)
    row.grid_columnconfigure(0, weight=1)
    ctk.CTkEntry(row, textvariable=var, height=38).grid(row=0, column=0, sticky="ew")
    btn = ctk.CTkButton(row, text=button_text, width=104, height=38, command=command,
                        fg_color=("gray75", "gray28"), hover_color=("gray65", "gray35"),
                        text_color=("gray10", "gray90"))
    btn.grid(row=0, column=1, padx=(8, 0))
    return btn


class PasswordField(ctk.CTkFrame):
    def __init__(self, master, show_strength=False):
        super().__init__(master, fg_color="transparent")
        self.grid_columnconfigure(0, weight=1)
        self.entry = ctk.CTkEntry(self, show="•", height=38)
        self.entry.grid(row=0, column=0, sticky="ew")
        self._shown = False
        self.toggle = ctk.CTkButton(self, text="Show", width=70, height=38, command=self._toggle,
                                    fg_color=("gray75", "gray28"), hover_color=("gray65", "gray35"),
                                    text_color=("gray10", "gray90"))
        self.toggle.grid(row=0, column=1, padx=(8, 0))
        self.show_strength = show_strength
        if show_strength:
            self.bar = ctk.CTkProgressBar(self, height=6)
            self.bar.set(0)
            self.bar.grid(row=1, column=0, sticky="ew", pady=(9, 0))
            self.lbl = ctk.CTkLabel(self, text="", width=70, anchor="w", font=ctk.CTkFont(size=12))
            self.lbl.grid(row=1, column=1, padx=(8, 0), pady=(9, 0))
            self.entry.bind("<KeyRelease>", lambda e: self._update())

    def _toggle(self):
        self._shown = not self._shown
        self.entry.configure(show="" if self._shown else "•")
        self.toggle.configure(text="Hide" if self._shown else "Show")

    def _update(self):
        score, label, color = password_strength(self.entry.get())
        self.bar.set(score / 4)
        self.bar.configure(progress_color=color)
        self.lbl.configure(text=label, text_color=color)

    def get(self):
        return self.entry.get()

    def clear(self):
        self.entry.delete(0, "end")
        if self.show_strength:
            self._update()

    def set_state(self, state):
        self.entry.configure(state=state)
        self.toggle.configure(state=state)


# ----------------------------- Lock page -----------------------------

class LockPage(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.folder_var, self.out_var = tk.StringVar(), tk.StringVar()
        self.delete_var = tk.BooleanVar(value=True)

        page_header(self, "Lock a folder",
                    "Compress and encrypt an entire folder into a single .vault file.\n"
                    "File names and folder structure are hidden too.")
        card = ctk.CTkFrame(self, corner_radius=14, fg_color=CARD)
        card.pack(fill="x", pady=(18, 0))

        field_label(card, "Folder to lock")
        self.b1 = path_row(card, self.folder_var, "Browse…", self.pick_folder)
        field_label(card, "Save vault as")
        self.b2 = path_row(card, self.out_var, "Change…", self.pick_out)
        field_label(card, "Password")
        self.pw = PasswordField(card, show_strength=True)
        self.pw.pack(fill="x", padx=22)
        field_label(card, "Confirm password")
        self.pw2 = PasswordField(card)
        self.pw2.pack(fill="x", padx=22)

        self.chk = ctk.CTkCheckBox(card, text="Delete the original folder after locking (vault is verified first)",
                                   variable=self.delete_var)
        self.chk.pack(anchor="w", padx=22, pady=(18, 0))
        ctk.CTkLabel(card, text="⚠  There is no password recovery. If you forget the password, the data is lost.",
                     text_color=("#B26A00", "#F5A524"), anchor="w",
                     font=ctk.CTkFont(size=12)).pack(fill="x", padx=22, pady=(10, 0))
        self.go = ctk.CTkButton(card, text="Lock folder", height=46, font=ctk.CTkFont(size=15, weight="bold"),
                                command=self.start)
        self.go.pack(fill="x", padx=22, pady=(16, 22))

    def pick_folder(self):
        p = filedialog.askdirectory(title="Choose the folder to lock")
        if p:
            p = os.path.abspath(p)
            self.folder_var.set(p)
            self.out_var.set(os.path.join(os.path.dirname(p), os.path.basename(p) + EXT))

    def pick_out(self):
        p = filedialog.asksaveasfilename(title="Save vault as", defaultextension=EXT,
                                         filetypes=[("Vault file", "*" + EXT)])
        if p:
            self.out_var.set(os.path.abspath(p))

    def refresh_state(self):
        st = "disabled" if self.app.busy else "normal"
        for w in (self.b1, self.b2, self.go, self.chk):
            w.configure(state=st)
        self.pw.set_state(st)
        self.pw2.set_state(st)

    def start(self):
        folder, out = self.folder_var.get().strip(), self.out_var.get().strip()
        if not folder or not os.path.isdir(folder):
            return messagebox.showerror(APP_NAME, "Please choose a valid folder.")
        folder = os.path.abspath(folder)
        if os.path.dirname(folder) == folder:
            return messagebox.showerror(APP_NAME, "You can't lock a drive root. Choose a folder.")
        if not out:
            return messagebox.showerror(APP_NAME, "Please choose where to save the vault.")
        out = os.path.abspath(out)
        if is_inside(out, folder):
            return messagebox.showerror(APP_NAME, "The vault file can't be saved inside the folder being locked.")
        pw = self.pw.get()
        if len(pw) < 8:
            return messagebox.showerror(APP_NAME, "The password must be at least 8 characters.")
        if pw != self.pw2.get():
            return messagebox.showerror(APP_NAME, "The passwords don't match.")
        if os.path.exists(out) and not messagebox.askyesno(APP_NAME, "The vault file already exists. Overwrite it?"):
            return
        delete = self.delete_var.get()
        if delete and not messagebox.askyesno(
                APP_NAME, "The original folder will be permanently deleted after the vault is created "
                          "and verified.\n\nContinue?"):
            return

        def job(task):
            fd, zpath = tempfile.mkstemp(prefix="vl_", suffix=".zip")
            os.close(fd)
            try:
                task.status = "Compressing folder…"
                zip_folder(folder, zpath, task.sub(0.0, 0.40))
                task.status = "Encrypting…"
                encrypt_file(zpath, out, pw, task.sub(0.40, 0.80))
            finally:
                remove_quietly(zpath)
            removed = None
            if delete:
                task.status = "Verifying vault…"
                verify_vault(out, pw, task.sub(0.80, 0.97))
                task.status = "Removing original folder…"
                removed = wipe_dir(folder)
            task.progress = 1.0
            return removed

        def done(removed):
            self.pw.clear()
            self.pw2.clear()
            msg = f"Folder locked successfully.\n\nVault: {out}"
            if removed is False:
                msg += "\n\nSome files in the original folder couldn't be deleted (in use?). Remove them manually."
            messagebox.showinfo(APP_NAME, msg)

        self.app.run_task(job, done)


# ----------------------------- Open page -----------------------------

class UnlockPage(ctk.CTkFrame):
    def __init__(self, master, app):
        super().__init__(master, fg_color="transparent")
        self.app = app
        self.vault_var = tk.StringVar()

        page_header(self, "Open a vault",
                    "Open it temporarily and lock it again when you're done, or extract it permanently.")
        card = ctk.CTkFrame(self, corner_radius=14, fg_color=CARD)
        card.pack(fill="x", pady=(18, 0))
        field_label(card, "Vault file")
        self.b1 = path_row(card, self.vault_var, "Browse…", self.pick_vault)
        field_label(card, "Password")
        self.pw = PasswordField(card)
        self.pw.pack(fill="x", padx=22)

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=22, pady=(20, 22))
        row.grid_columnconfigure((0, 1), weight=1, uniform="b")
        self.open_btn = ctk.CTkButton(row, text="Open temporarily", height=46,
                                      font=ctk.CTkFont(size=15, weight="bold"), command=self.open_temp)
        self.open_btn.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.ext_btn = ctk.CTkButton(row, text="Extract to…", height=46, command=self.extract_to,
                                     font=ctk.CTkFont(size=15),
                                     fg_color=("gray75", "gray28"), hover_color=("gray65", "gray35"),
                                     text_color=("gray10", "gray90"))
        self.ext_btn.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        # session card (shown while a vault is open)
        self.sess = ctk.CTkFrame(self, corner_radius=14, fg_color=CARD, border_width=2,
                                 border_color="#30A46C")
        self.sess_title = ctk.CTkLabel(self.sess, text="", anchor="w",
                                       font=ctk.CTkFont(size=15, weight="bold"))
        self.sess_title.pack(fill="x", padx=22, pady=(16, 0))
        self.sess_info = ctk.CTkLabel(self.sess, text="", anchor="w", justify="left",
                                      text_color=MUTED, font=ctk.CTkFont(size=12))
        self.sess_info.pack(fill="x", padx=22, pady=(2, 0))
        srow = ctk.CTkFrame(self.sess, fg_color="transparent")
        srow.pack(fill="x", padx=22, pady=(14, 18))
        srow.grid_columnconfigure((0, 1, 2), weight=1, uniform="s")
        self.show_btn = ctk.CTkButton(srow, text="Show folder", height=40, command=self.show_folder,
                                      fg_color=("gray75", "gray28"), hover_color=("gray65", "gray35"),
                                      text_color=("gray10", "gray90"))
        self.show_btn.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        self.save_btn = ctk.CTkButton(srow, text="Save & lock", height=40, command=self.save_lock,
                                      fg_color=GREEN, hover_color="#258A5A",
                                      font=ctk.CTkFont(weight="bold"))
        self.save_btn.grid(row=0, column=1, sticky="ew", padx=5)
        self.disc_btn = ctk.CTkButton(srow, text="Discard & lock", height=40, command=self.discard,
                                      fg_color="transparent", border_width=1, border_color=RED,
                                      text_color=RED, hover_color=("gray85", "gray25"))
        self.disc_btn.grid(row=0, column=2, sticky="ew", padx=(5, 0))

    def pick_vault(self):
        p = filedialog.askopenfilename(title="Choose a vault file",
                                       filetypes=[("Vault file", "*" + EXT), ("All files", "*.*")])
        if p:
            self.vault_var.set(os.path.abspath(p))

    def refresh_state(self):
        s = self.app.session
        busy = self.app.busy
        st_open = "disabled" if (busy or s) else "normal"
        for w in (self.b1, self.open_btn, self.ext_btn):
            w.configure(state=st_open)
        self.pw.set_state(st_open)
        st_sess = "disabled" if busy else "normal"
        for w in (self.show_btn, self.save_btn, self.disc_btn):
            w.configure(state=st_sess)
        if s:
            self.sess_title.configure(text=f"●  Vault is open — {os.path.basename(s['vault'])}")
            self.sess_info.configure(
                text=f"Working folder: {s['dir']}\nChanges are encrypted back into the vault when you press “Save & lock”.")
            self.sess.pack(fill="x", pady=(16, 0))
        else:
            self.sess.pack_forget()

    def _check(self):
        vault = self.vault_var.get().strip()
        if not vault or not os.path.isfile(vault):
            messagebox.showerror(APP_NAME, "Please choose a valid vault file.")
            return None
        if not self.pw.get():
            messagebox.showerror(APP_NAME, "Please enter the password.")
            return None
        return os.path.abspath(vault), self.pw.get()

    def open_temp(self):
        chk = self._check()
        if not chk:
            return
        vault, pw = chk

        def job(task):
            fd, zpath = tempfile.mkstemp(prefix="vl_", suffix=".zip")
            os.close(fd)
            sdir = tempfile.mkdtemp(prefix="vaultlocker_")
            try:
                task.status = "Decrypting…"
                decrypt_to_file(vault, zpath, pw, task.sub(0.0, 0.6))
                task.status = "Extracting…"
                unzip_to(zpath, sdir, task.sub(0.6, 1.0))
            except BaseException:
                wipe_dir(sdir)
                raise
            finally:
                remove_quietly(zpath)
            return sdir

        def done(sdir):
            self.app.session = {"vault": vault, "dir": sdir, "password": pw}
            self.pw.clear()
            self.app.refresh_all()
            open_in_file_manager(sdir)

        self.app.run_task(job, done)

    def extract_to(self):
        chk = self._check()
        if not chk:
            return
        vault, pw = chk
        parent = filedialog.askdirectory(title="Choose where to extract")
        if not parent:
            return
        target = os.path.join(parent, os.path.splitext(os.path.basename(vault))[0])
        existed = os.path.exists(target)
        if existed and os.listdir(target) and not messagebox.askyesno(
                APP_NAME, f"'{target}' already contains files.\nExtract into it anyway (existing files with the "
                          f"same name will be overwritten)?"):
            return

        def job(task):
            fd, zpath = tempfile.mkstemp(prefix="vl_", suffix=".zip")
            os.close(fd)
            try:
                task.status = "Decrypting…"
                decrypt_to_file(vault, zpath, pw, task.sub(0.0, 0.6))
                task.status = "Extracting…"
                unzip_to(zpath, target, task.sub(0.6, 1.0))
            except BaseException:
                if not existed:
                    wipe_dir(target)
                raise
            finally:
                remove_quietly(zpath)

        def done(_):
            self.pw.clear()
            messagebox.showinfo(APP_NAME, f"Extracted to:\n{target}")
            open_in_file_manager(target)

        self.app.run_task(job, done)

    def show_folder(self):
        if self.app.session:
            open_in_file_manager(self.app.session["dir"])

    def save_lock(self):
        self.app.save_session()

    def discard(self):
        s = self.app.session
        if not s:
            return
        if not messagebox.askyesno(APP_NAME, "Discard all changes made since opening and lock the vault again?\n"
                                             "The vault file stays exactly as it was."):
            return

        def job(task):
            task.status = "Cleaning up…"
            wipe_dir(s["dir"])
            task.progress = 1.0

        def done(_):
            self.app.session = None
            self.app.refresh_all()

        self.app.run_task(job, done)


# ----------------------------- Main window -----------------------------

class App(ctk.CTk):
    def __init__(self, open_path=None):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("940x700")
        self.minsize(880, 660)
        self.busy = False
        self.session = None
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_content()
        self.show("lock")
        self.refresh_all()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        if open_path and os.path.isfile(open_path):
            page = self.pages["unlock"]
            page.vault_var.set(os.path.abspath(open_path))
            self.show("unlock")
            self.after(300, lambda: (self.lift(), page.pw.entry.focus_force()))

    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color=("gray86", "gray14"))
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        ctk.CTkLabel(sb, text="🔒  Vault Locker", font=ctk.CTkFont(size=20, weight="bold"),
                     anchor="w").pack(fill="x", padx=22, pady=(28, 2))
        ctk.CTkLabel(sb, text="Encrypted folders, one file.", text_color=MUTED, anchor="w",
                     font=ctk.CTkFont(size=12)).pack(fill="x", padx=22, pady=(0, 24))
        self.nav = {}
        for key, label in (("lock", "🔐   Lock folder"), ("unlock", "📂   Open vault")):
            b = ctk.CTkButton(sb, text=label, anchor="w", height=42, corner_radius=8,
                              fg_color="transparent", text_color=("gray10", "gray90"),
                              hover_color=("gray78", "gray25"), font=ctk.CTkFont(size=14),
                              command=lambda k=key: self.show(k))
            b.pack(fill="x", padx=14, pady=3)
            self.nav[key] = b
        ctk.CTkLabel(sb, text="AES-256-GCM\nscrypt key derivation\nAuthenticated & tamper-proof",
                     text_color=MUTED, justify="left", anchor="w",
                     font=ctk.CTkFont(size=11)).pack(side="bottom", fill="x", padx=22, pady=22)

    def _build_content(self):
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=1)
        self.pages = {"lock": LockPage(content, self), "unlock": UnlockPage(content, self)}
        for p in self.pages.values():
            p.grid(row=0, column=0, sticky="nsew", padx=34, pady=(30, 8))
        bar = ctk.CTkFrame(content, fg_color="transparent")
        bar.grid(row=1, column=0, sticky="ew", padx=34, pady=(0, 22))
        bar.grid_columnconfigure(0, weight=1)
        self.status = ctk.CTkLabel(bar, text="Ready", anchor="w", text_color=MUTED,
                                   font=ctk.CTkFont(size=12))
        self.status.grid(row=0, column=0, sticky="w")
        self.progress = ctk.CTkProgressBar(bar, height=8)
        self.progress.set(0)
        self.progress.grid(row=1, column=0, sticky="ew", pady=(6, 0))

    def show(self, key):
        self.pages[key].tkraise()
        for k, b in self.nav.items():
            b.configure(fg_color=("gray78", "gray25") if k == key else "transparent")

    def refresh_all(self):
        for p in self.pages.values():
            p.refresh_state()

    def set_busy(self, busy):
        self.busy = busy
        self.refresh_all()

    # --- task runner -------------------------------------------------
    def run_task(self, fn, on_success=None):
        self.set_busy(True)
        task = Task(fn)

        def poll():
            self.progress.set(task.progress)
            if task.status:
                self.status.configure(text=task.status)
            if not task.done:
                self.after(60, poll)
                return
            self.set_busy(False)
            self.progress.set(0)
            self.status.configure(text="Ready")
            if task.error:
                self.show_error(task.error)
            elif on_success:
                on_success(task.result)

        poll()

    def show_error(self, err):
        if isinstance(err, WrongPassword):
            msg = "Wrong password, or the vault file is damaged."
        elif isinstance(err, VaultError):
            msg = str(err)
        elif isinstance(err, OSError):
            msg = f"File system error:\n{err.strerror or err}"
        else:
            msg = f"Unexpected error:\n{err}"
        messagebox.showerror(APP_NAME, msg)

    # --- session handling ----------------------------------------------
    def save_session(self, on_done=None):
        s = self.session
        if not s:
            return

        def job(task):
            fd, zpath = tempfile.mkstemp(prefix="vl_", suffix=".zip")
            os.close(fd)
            try:
                task.status = "Compressing changes…"
                zip_folder(s["dir"], zpath, task.sub(0.0, 0.40))
                task.status = "Encrypting…"
                encrypt_file(zpath, s["vault"], s["password"], task.sub(0.40, 0.90))
            finally:
                remove_quietly(zpath)
            task.status = "Cleaning up…"
            ok = wipe_dir(s["dir"])
            task.progress = 1.0
            return ok

        def done(ok):
            self.session = None
            self.refresh_all()
            if not ok:
                messagebox.showwarning(APP_NAME, "Vault saved, but some temporary files couldn't be removed:\n"
                                                 f"{s['dir']}\nClose programs using them and delete the folder.")
            if on_done:
                on_done()

        self.run_task(job, done)

    def on_close(self):
        if self.busy:
            return messagebox.showinfo(APP_NAME, "Please wait for the current operation to finish.")
        if self.session:
            ans = messagebox.askyesnocancel(
                APP_NAME, "A vault is still open.\n\nYes — save changes and lock it\n"
                          "No — discard changes and exit\nCancel — keep working")
            if ans is None:
                return
            if ans:
                return self.save_session(on_done=self.destroy)
            wipe_dir(self.session["dir"])
        self.destroy()


if __name__ == "__main__":
    App(sys.argv[1] if len(sys.argv) > 1 else None).mainloop()
