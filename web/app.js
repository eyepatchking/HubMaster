"use strict";

const words = {
  policy_limit:["Saqlangan qurilma qoidalari chegarasiga yetildi","Достигнут лимит правил устройств","Stored device policy limit reached"],
  changePassword:["Parolni almashtirish","Изменить пароль","Change password"], currentPassword:["Joriy parol","Текущий пароль","Current password"], confirmPassword:["Yangi parolni takrorlang","Повторите новый пароль","Confirm new password"], passwordMismatch:["Parollar mos emas","Пароли не совпадают","Passwords do not match"], exportAudit:["Auditni yuklab olish","Скачать аудит","Export audit"], localRecovery:["Parol va tiklash kaliti yo‘q bo‘lsa: Start menyusidagi HubMaster Admin Recovery ni Windows administrator huquqi bilan oching.","Если пароль и ключ утеряны, откройте HubMaster Admin Recovery из меню Пуск с правами администратора Windows.","If both password and recovery key are lost, open HubMaster Admin Recovery from Start with Windows administrator privileges."],
  theme:["Rang rejimi","Тема","Theme"], system:["Tizim","Системная","System"], light:["Yorug‘","Светлая","Light"], dark:["Qorong‘i","Тёмная","Dark"],
  dashboard:["Boshqaruv paneli","Панель управления","Dashboard"], computers:["Kompyuterlar","Компьютеры","Computers"],
  audit:["Audit jurnali","Журнал аудита","Audit log"], logout:["Chiqish","Выйти","Sign out"], lan:["Mahalliy tarmoq","Локальная сеть","Local network"],
  search:["Kompyuter yoki IP bo‘yicha qidiring","Поиск по имени или IP","Search by computer or IP"],
  scan:["Scan","Сканировать","Scan"], scanning:["Qidirilmoqda…","Поиск…","Scanning…"],
  overview:["Qurilmalar nazorati","Контроль устройств","Device monitoring"],
  overviewText:["USB, xotira qurilmalari va agentlar holati","USB, накопители и состояние агентов","USB, removable media and agent status"],
  total:["Kompyuterlar","Компьютеры","Computers"], online:["Onlayn","В сети","Online"], offline:["Oflayn","Не в сети","Offline"],
  blocked:["Bloklangan","Заблокировано","Blocked"], status:["Holat","Статус","Status"], host:["Kompyuter","Компьютер","Computer"],
  ports:["Portlar","Порты","Ports"], devices:["Qurilmalar","Устройства","Devices"], last:["Oxirgi aloqa","Последняя связь","Last seen"],
  recent:["Oxirgi hodisalar","Последние события","Recent activity"], local:["Admin kompyuteri","Компьютер администратора","Admin PC"],
  hostEvents:["Kompyuter hodisalari","События компьютера","Computer events"],
  showMenu:["Menyuni ko‘rsatish","Показать меню","Show menu"], hideMenu:["Menyuni yashirish","Скрыть меню","Hide menu"],
  showActivity:["Hodisalarni ko‘rsatish","Показать события","Show activity"], hideActivity:["Hodisalarni yashirish","Скрыть события","Hide activity"],
  waiting:["Kutilmoqda","Ожидание","Pending"], removed:["Olib tashlangan","Удалён","Removed"], none:["Hozircha yozuv yo‘q","Пока записей нет","No records yet"],
  noMatch:["Mos kompyuter topilmadi","Подходящие компьютеры не найдены","No matching computers"],
  name:["Nomi","Имя","Name"], kind:["Turi","Тип","Type"], identity:["Identifikator","Идентификатор","Identity"], policy:["Qoida","Правило","Policy"],
  block:["Bloklash","Блокировать","Block"], allow:["Ruxsat berish","Разрешить","Allow"], allowed:["Ruxsatli","Разрешено","Allowed"],
  disconnected:["Uzilgan","Отключено","Disconnected"], occupied:["Band","Занят","Connected"], empty:["Bo‘sh","Свободен","Empty"],
  hidOn:["BadUSB himoyasini yoqish","Включить защиту BadUSB","Enable BadUSB protection"],
  hidOff:["BadUSB himoyasini o‘chirish","Отключить защиту BadUSB","Disable BadUSB protection"],
  hidExplain:["Hozir ulangan klaviatura va sichqonchalar ruxsatli qoladi. Yangi USB klaviatura yoki sichqoncha aniqlansa, agent uni bloklashga urinadi.",
    "Подключённые клавиатуры и мыши останутся разрешёнными. При обнаружении новой USB-клавиатуры или мыши агент попытается её заблокировать.",
    "Currently connected keyboards and mice stay trusted. When a new USB keyboard or mouse is detected, the agent attempts to block it."],
  remove:["Agentni olib tashlash","Удалить агент","Remove agent"],
  removeExplain:["Agent HubMaster bloklarini yechadi va fon xizmatini olib tashlaydi. Keyin agentni Windows dasturlari ro‘yxatidan o‘chirish mumkin.",
    "Агент снимет блокировки HubMaster и удалит фоновую службу. Затем приложение можно удалить из списка программ Windows.",
    "The agent releases HubMaster blocks and removes its background service. The application can then be removed from Windows Installed apps."],
  removing:["Olib tashlash kutilmoqda","Ожидается удаление","Removal pending"],
  applied:["Qoida saqlandi","Правило сохранено","Policy saved"], back:["Orqaga","Назад","Back"], close:["Yopish","Закрыть","Close"],
  cancel:["Bekor qilish","Отмена","Cancel"], confirm:["Tasdiqlash","Подтвердить","Confirm"], time:["Vaqt","Время","Time"],
  event:["Hodisa","Событие","Event"], item:["Fayl yoki qurilma","Файл или устройство","File or device"], detail:["Tafsilot","Подробности","Details"],
  older:["Avvalgi yozuvlar","Предыдущие записи","Older records"], latest:["Eng yangi","Последние","Latest"],
  setup:["Admin parolini yarating","Создайте пароль администратора","Create an admin password"], login:["Admin paneliga kirish","Вход в панель","Sign in to Admin"],
  reset:["Parolni tiklash","Сброс пароля","Reset password"], password:["Parol","Пароль","Password"],
  newPassword:["Yangi parol","Новый пароль","New password"], recovery:["Tiklash kaliti","Ключ восстановления","Recovery key"],
  save:["Saqlash","Сохранить","Save"], signin:["Kirish","Войти","Sign in"], copy:["Nusxalash","Копировать","Copy"],
  copied:["Nusxalandi","Скопировано","Copied"],
  recoveryHelp:["Kalitni xavfsiz joyga saqlang. Parolni tiklash uchun shu kalit kerak bo‘ladi.",
    "Сохраните ключ в надёжном месте. Он потребуется для сброса пароля.","Store this key securely. You will need it to reset your password."],
  setupKey:["Boshlash uchun Start menyusidan HubMaster Admin dasturini oching.",
    "Для настройки откройте HubMaster Admin из меню «Пуск».","Open HubMaster Admin from the Start menu to complete setup."],
  password_length:["Parol 6 belgidan iborat bo‘lsin. Katta va kichik harf, raqam va maxsus belgi kiriting.","Пароль должен состоять из 6 символов и включать заглавную и строчную буквы, цифру и знак.","Use 6 characters, including uppercase and lowercase letters, a digit and a symbol."],
  credentials:["Parol yoki tiklash kaliti xato.","Неверный пароль или ключ.","The password or key is incorrect."],
  rate:["Biroz kutib, yana urinib ko‘ring.","Подождите и повторите попытку.","Wait a moment and try again."],
  invalid:["So‘rovni bajarib bo‘lmadi.","Не удалось выполнить запрос.","The request could not be completed."],
  service:["Xizmatda xato yuz berdi.","Ошибка службы.","The service encountered an error."],
  audit_error:["Audit jurnaliga yozib bo‘lmadi.","Не удалось записать в журнал.","The audit log could not be written."],
  scan_error:["Tarmoqni skanerlab bo‘lmadi.","Не удалось просканировать сеть.","Could not scan the network."],
  pair_pending:["Agent javobi kelmadi. Holatni kompyuterlar ro‘yxatidan tekshiring.",
    "Ответ агента не получен. Проверьте состояние в списке компьютеров.","No reply from the agent. Check its status in the computer list."],
  otp:["Kod xato, eskirgan yoki urinishlar tugagan.","Код неверен, истёк или исчерпаны попытки.","Incorrect or expired code, or no attempts remain."],
  pair:["Bog‘lash","Подключить","Pair"], otpLabel:["6 xonali OTP","6-значный код","6-digit OTP"],
  found:["Topilgan agentlar","Найденные агенты","Discovered agents"],
  noAgents:["Agent.exe’ni mijoz kompyuterda ochib, OTP chiqqach yana Scan tugmasini bosing.",
    "Откройте Agent.exe на клиенте. После появления кода повторите сканирование.","Open Agent.exe on the client. When the OTP appears, scan again."],
  paired:["Agent bog‘landi","Агент подключён","Agent paired"],
  serial:["Seriya raqami","Серийный номер","Serial number"], instance:["Windows ID","ID Windows","Windows ID"],
  storage:["USB xotira","USB-накопитель","USB storage"], sd:["SD karta","SD-карта","SD card"], sdreader:["SD o‘quvchi","Кардридер SD","SD reader"],
  optical:["CD/DVD","CD/DVD","CD/DVD"], usb:["USB","USB","USB"], usb_c:["USB-C","USB-C","USB-C"],
  keyboard:["Klaviatura","Клавиатура","Keyboard"], mouse:["Sichqoncha","Мышь","Mouse"], hid:["HID","HID","HID"],
  printer:["Printer","Принтер","Printer"], portable:["Portativ qurilma","Портативное устройство","Portable device"],
  "device.connected":["Qurilma ulandi","Устройство подключено","Device connected"],
  "device.disconnected":["Qurilma uzildi","Устройство отключено","Device disconnected"],
  "device.blocked":["Qurilma bloklandi","Устройство заблокировано","Device blocked"],
  "device.allowed":["Qurilmaga ruxsat berildi","Устройство разрешено","Device allowed"],
  "device.hid_alert":["Yangi USB klaviatura yoki sichqoncha","Новая USB-клавиатура или мышь","New USB keyboard or mouse"],
  "device.error":["Qurilma xatosi","Ошибка устройства","Device error"],
  "file.created":["Fayl yaratildi yoki ko‘chirildi","Файл создан или скопирован","File created or copied"],
  "file.modified":["Fayl o‘zgardi","Файл изменён","File modified"], "file.deleted":["Fayl o‘chirildi","Файл удалён","File deleted"],
  "file.renamed":["Fayl nomi o‘zgardi","Файл переименован","File renamed"],
  "file.rename_from":["Eski fayl nomi","Прежнее имя файла","Previous filename"],
  "file.process":["Faylga dastur murojaati","Доступ программы к файлу","Process file access"],
  "agent.paired":["Agent bog‘landi","Агент подключён","Agent paired"],
  "agent.removed":["Agent olib tashlandi","Агент удалён","Agent removed"],
  "audit.gap":["Auditda uzilish","Разрыв аудита","Audit gap"], "audit.error":["Audit xatosi","Ошибка аудита","Audit error"],
  "password.changed":["Parol almashtirildi","Пароль изменён","Password changed"],
  "password.recovery_authorized":["Windows administratori tiklashni boshladi","Восстановление разрешено администратором Windows","Recovery authorized by Windows administrator"],
  "password.setup":["Admin paroli yaratildi","Пароль создан","Admin password created"],
  "password.reset":["Admin paroli tiklandi","Пароль сброшен","Admin password reset"],
  "policy.allow":["Ruxsat berish qoidasi","Правило разрешения","Allow policy"],
  "policy.block":["Bloklash qoidasi","Правило блокировки","Block policy"],
  "policy.hid_on":["BadUSB himoyasi yoqildi","Защита BadUSB включена","BadUSB protection enabled"],
  "policy.hid_off":["BadUSB himoyasi o‘chirildi","Защита BadUSB выключена","BadUSB protection disabled"],
  "policy.remove":["Agentni olib tashlashga ruxsat","Удаление агента разрешено","Agent removal authorized"]
};

words.hidOn=["Yangi HID qurilmalarini nazorat qilish","Контроль новых HID-устройств","Monitor new HID devices"];
words.hidOff=["HID nazoratini o‘chirish","Отключить контроль HID","Disable HID monitoring"];
words.hidExplain=["Hozir ulangan HID qurilmalari ruxsatli qoladi. Agent yangi HID qurilmalarini davriy tekshiradi va bloklashga urinadi; qurilma bloklanguncha ishlashi mumkin.","Подключённые HID-устройства останутся доверенными. Агент периодически проверяет и блокирует новые устройства; до блокировки устройство может успеть сработать.","Connected HID devices remain trusted. The agent polls and attempts to block new HID devices; a device may act before it is blocked."];
words.uncontrollable=["Bu qurilmani bloklash qo‘llanmaydi","Блокировка этого устройства недоступна","Blocking this device is unavailable"];
words.password_length=["Parol 12–128 belgidan iborat bo‘lsin: katta va kichik harf, raqam hamda belgi ishlating.","Пароль: 12–128 символов, прописные и строчные буквы, цифра и спецсимвол.","Use 12–128 characters with uppercase and lowercase letters, a digit and a symbol."];
let theme = localStorage.getItem("hm_theme") || "system";
const systemTheme = matchMedia("(prefers-color-scheme: dark)");
function applyTheme() {
  document.documentElement.dataset.theme = theme === "system" ? (systemTheme.matches ? "dark" : "light") : theme;
}
systemTheme.addEventListener("change", applyTheme);
applyTheme();
const app = document.getElementById("app");
const dialog = document.getElementById("dialog");
const languages = ["uz","ru","en"];
let language = Math.max(0,languages.indexOf(localStorage.getItem("hm_language")));
let setupKey = new URLSearchParams(location.hash.slice(1)).get("setup") || "";
if (location.hash) history.replaceState(null,"",location.pathname);
let auth = null, resetting = false, view = "dashboard", selected = "", tab = "devices", query = "";
let hosts = [], events = [], auditBefore = 0, auditPage = 0;
let hostEvents = [], hostBefore = 0, hostPage = 0;
let menuHidden = localStorage.getItem("hm_menu_hidden")==="1";
let activityHidden = localStorage.getItem("hm_activity_hidden")==="1";
let refreshing = false, toastTimer;

const t = key => words[key]?.[language] || key;
const esc = value => String(value ?? "").replace(/[&<>"']/g,ch=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[ch]));
const brand = '<div class="brand"><img class="mark" src="/logo.png" alt=""><span class="brand-label">HubMaster</span></div>';
const icon = '<svg viewBox="0 0 90 68" fill="none" stroke="currentColor" stroke-width="3" aria-hidden="true"><rect x="9" y="7" width="72" height="44" rx="6"/><path d="M30 60h30M45 51v9M26 34l9-9 8 8 15-13 7 7"/><circle cx="64" cy="27" r="2" fill="currentColor"/></svg>';
const date = value => !value || value.startsWith("0001") ? "—" : new Date(value).toLocaleString(languages[language],{dateStyle:"short",timeStyle:"short"});
const badge = key => `<span class="badge ${key}">${t(key)}</span>`;
const blank = key => `<div class="empty">${t(key)}</div>`;
const iconPaths = {
  dashboard:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  computers:'<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  audit:'<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6M8 13h8m-8 4h6"/>',
  key:'<circle cx="8" cy="8" r="5"/><path d="m11.5 11.5 9 9M16 16l3-3m-6 0 3-3"/>',
  reset:'<path d="M3 11a9 9 0 1 1 2.6 7M3 4v7h7"/><path d="M12 8v5l3 2"/>',
  download:'<path d="M12 3v12m-5-5 5 5 5-5M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
  logout:'<path d="M9 4H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4m7-13 5 5-5 5M9 12h12"/>',
  menu:'<path d="M4 6h16M4 12h16M4 18h16"/>',
  panel:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M15 4v16"/>',
  scan:'<path d="M8 3H4v5m12-5h4v5M4 16v5h4m12-5v5h-4M8 12h8m-4-4v8"/>',
  back:'<path d="m10 5-7 7 7 7M3 12h18"/>',
  close:'<path d="m6 6 12 12M6 18 18 6"/>',
  copy:'<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
  shield:'<path d="M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7z"/><path d="m8 12 3 3 5-6"/>',
  remove:'<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
  save:'<path d="M4 3h13l4 4v14H3V3zM7 3v6h9V3M7 21v-7h10v7"/>',
  network:'<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v5M5 17v-5h14v5"/>'
};
const uiIcon = name => `<svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${iconPaths[name]||iconPaths.panel}</svg>`;
const actionIcon = action => ({"change-password":"key",reset:"reset",logout:"logout",scan:"scan",back:"back",close:"close",copy:"copy",hid_on:"shield",hid_off:"shield",remove:"remove",save:"save",confirm:"save",older:"back",latest:"reset","host-older":"back","host-latest":"reset"})[action];
const button = (label,action,style="secondary") => `<button type="button" class="${style}" data-action="${action}" title="${esc(t(label))}">${actionIcon(action)?uiIcon(actionIcon(action)):""}<span class="button-label">${t(label)}</span></button>`;
const sidebar = () => `<aside class="side" id="navigation"><div class="brand" title="HubMaster"><img class="mark" src="/logo.png" alt="HubMaster"><span class="brand-label">HubMaster</span></div><nav class="nav" aria-label="${esc(t("dashboard"))}">
${["dashboard","computers","audit"].map(key=>`<button data-action="nav-${key}" title="${esc(t(key))}" aria-label="${esc(t(key))}" ${view===key?'aria-current="page"':""}>${uiIcon(key)}<span class="nav-label">${t(key)}</span></button>`).join("")}
</nav><div class="sidefoot"><button class="side-action" data-action="change-password" title="${esc(t("changePassword"))}" aria-label="${esc(t("changePassword"))}">${uiIcon("key")}<span class="nav-label">${t("changePassword")}</span></button><a class="side-action" href="/api/audit/export" title="${esc(t("exportAudit"))}" aria-label="${esc(t("exportAudit"))}">${uiIcon("download")}<span class="nav-label">${t("exportAudit")}</span></a><button class="side-action logout" data-action="logout" title="${esc(t("logout"))}" aria-label="${esc(t("logout"))}">${uiIcon("logout")}<span class="nav-label">${t("logout")}</span></button><div class="lan" title="${esc(t("lan"))}" aria-label="${esc(t("lan"))}">${uiIcon("network")}<span class="nav-label">${t("lan")}</span><span class="light" aria-hidden="true"></span></div></div></aside>`;

const themePicker = () => `<select id="theme" class="language" aria-label="${t("theme")}">${["system","light","dark"].map(value=>`<option value="${value}" ${theme===value?"selected":""}>${t(value)}</option>`).join("")}</select>`;
const languagePicker = () => `<select id="language" class="language" aria-label="Language"><option value="0">O‘zbekcha</option><option value="1">Русский</option><option value="2">English</option></select>`;

async function api(path, body) {
  const res = await fetch("/api/"+path, body === undefined ? {} : {
    method:"POST",headers:{"Content-Type":"application/json","X-HubMaster":"admin"},body:JSON.stringify(body)
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || "service");
  return json;
}

function notify(message) {
  const box = document.getElementById("toast");
  box.textContent = t(message);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>{box.textContent="";},4500);
}

function renderAuth() {
  const mode = auth?.setup ? "setup" : resetting ? "reset" : "login";
  app.innerHTML = `<div class="auth-shell"><section class="auth">${themePicker()}${languagePicker()}${brand}<h1>${t(mode)}</h1>
    ${mode==="setup" && !setupKey ? `<p class="notice">${t("setupKey")}</p>` : `<form id="authForm">
      ${mode==="reset" ? `<label>${t("recovery")}<input name="key" required maxlength="64" autocomplete="off"></label>` : ""}
      <label>${t(mode==="login"?"password":"newPassword")}<input name="password" type="password" required ${mode==="login"?'maxlength="256" autocomplete="current-password"':'minlength="12" maxlength="128" autocomplete="new-password"'}></label>
      ${mode!=="login" ? `<label>${t("confirmPassword")}<input name="confirm" type="password" required minlength="12" maxlength="128" autocomplete="new-password"></label><p class="muted">${t("password_length")}</p>` : ""}
      <p class="error" aria-live="polite" id="authError"></p>
      <button class="primary" type="submit">${uiIcon(mode==="login"?"logout":mode==="reset"?"reset":"save")}${t(mode==="login"?"signin":"save")}</button></form>`}
    ${mode==="setup" ? "" : button(resetting?"back":"reset","reset","link")}<p class="muted recovery-help">${t("localRecovery")}</p></section></div>`;
  const form = document.getElementById("authForm");
  form?.addEventListener("submit", async ev=>{
    ev.preventDefault();
    const send=form.querySelector("button");
    send.disabled=true;
    try {
      const data = new FormData(form);
      if(mode!=="login" && data.get("password")!==data.get("confirm")) throw new Error("passwordMismatch");
      const result = await api("auth/"+mode,{Password:data.get("password"),Key:mode==="setup"?setupKey:(data.get("key")||"")});
      setupKey="";
      resetting=false;
      auth={authenticated:true};
      render();
      await refresh();
      if (result.recovery) showRecovery(result.recovery);
    } catch (err) {
      document.getElementById("authError").textContent=t(err.message);
    } finally { send.disabled=false; }
  });
}

function render() {
  const previousScroll=document.querySelector("#content .scroll, #content .port-list");
  const previousTop=previousScroll?.scrollTop||0, previousLeft=previousScroll?.scrollLeft||0;
  document.documentElement.lang=languages[language];
  if (!auth?.authenticated) {
    renderAuth();
  } else {
    app.innerHTML = `<div class="shell ${menuHidden?"menu-hidden":""}">${sidebar()}
      <main class="main"><header class="top"><button class="small toggle" data-action="toggle-menu" aria-controls="navigation" aria-expanded="${!menuHidden}" title="${esc(t(menuHidden?"showMenu":"hideMenu"))}" aria-label="${esc(t(menuHidden?"showMenu":"hideMenu"))}">${uiIcon("menu")}<span class="button-label">${t(menuHidden?"showMenu":"hideMenu")}</span></button><input id="search" class="search" type="search" aria-label="${t("search")}" placeholder="${t("search")}" value="${esc(query)}"><button class="small toggle" data-action="toggle-activity" aria-controls="activity" aria-expanded="${!activityHidden}">${uiIcon("panel")}<span class="button-label">${t(activityHidden?"showActivity":"hideActivity")}</span></button>${themePicker()}${languagePicker()}</header>
      <div class="split ${activityHidden?"activity-hidden":""}"><section class="content" id="content"></section><aside class="aside" id="activity"></aside></div></main></div>`;
    document.getElementById("search").addEventListener("input",e=>{
      query=e.target.value;
      if (view==="audit") { view="computers"; selected=""; }
      renderData();
    });
    renderData();
    const nextScroll=document.querySelector("#content .scroll, #content .port-list");
    if (nextScroll) { nextScroll.scrollTop=previousTop; nextScroll.scrollLeft=previousLeft; }
  }
  const themeSelect=document.getElementById("theme");
  themeSelect.onchange=()=>{theme=themeSelect.value;localStorage.setItem("hm_theme",theme);applyTheme();};
  const picker=document.getElementById("language");
  picker.value=String(language);
  picker.onchange=()=>{
    language=Number(picker.value);
    localStorage.setItem("hm_language",languages[language]);
    render();
  };
}

function hostStatus(h) {
  if (h.removed) return "removed";
  if (h.policy.remove) return "waiting";
  return Date.now()-new Date(h.last).getTime()<22000 ? "online" : "offline";
}

function hostRows() {
  const filter=query.trim().toLocaleLowerCase();
  const filtered=hosts.filter(h=>h.name.toLocaleLowerCase().includes(filter)||h.address.includes(filter));
  if (!filtered.length) return blank(filter?"noMatch":"none");
  return `<div class="box scroll"><table><thead><tr><th>${t("host")}</th><th>${t("status")}</th><th>${t("ports")}</th><th>${t("last")}</th></tr></thead><tbody>
    ${filtered.map(h=>`<tr class="host-row"><td><button class="host-btn" data-host="${esc(h.id)}">${esc(h.name)}</button><span class="host-id">${h.local?t("local"):esc(h.address)}</span></td>
    <td>${badge(hostStatus(h))}</td><td>${h.ports?.length??"—"}</td><td>${esc(date(h.last))}</td></tr>`).join("")}</tbody></table></div>`;
}

function deviceRows(h) {
  if (!h.devices?.length) return blank("none");
  return `<div class="box scroll"><table><thead><tr><th>${t("devices")}</th><th>${t("ports")}</th><th>${t("status")}</th><th>${t("policy")}</th></tr></thead><tbody>
    ${h.devices.map(d=>{
      const rule=h.policy.devices?.[d.id];
      const action=rule==="block"||d.blocked?"allow":"block";
      return `<tr><td><strong>${esc(d.name)}</strong><span class="host-id">${esc(t(d.kind))} · ${esc(d.hardware||d.id)}${d.serial?` · SN ${esc(d.serial)}`:""}</span></td><td>${esc(d.port||"—")}</td>
        <td>${badge(d.blocked?"blocked":d.present?"allowed":"disconnected")}</td><td>${d.controllable&&!h.policy.remove?`<button class="small" data-policy="${action}" data-device="${esc(d.id)}">${uiIcon(action==="allow"?"shield":"remove")}${t(action)}</button>`:esc(t("uncontrollable"))}</td></tr>`;
    }).join("")}</tbody></table></div>`;
}

function portRows(h) {
  if (!h.ports?.length) return blank("none");
  return `<div class="port-list">${h.ports.map(p=>`<article class="box port-item"><strong>${esc(p.name)}</strong><p class="muted">${esc(t(p.kind))} · ${t(p.connected?"occupied":"empty")}</p>
    ${(h.devices||[]).filter(d=>d.present&&d.port===p.name).map(d=>`<p>${esc(d.name)}</p>`).join("")}</article>`).join("")}</div>`;
}

function detail(h) {
  return `<div class="topline">${button("back","back")}</div><div class="box detail-head"><div><h1>${esc(h.name)}</h1><p class="muted">${h.local?t("local"):esc(h.address)} · ${esc(date(h.last))}</p></div>${badge(hostStatus(h))}</div>
    ${h.health?`<p class="notice">${esc(h.health)}</p>`:""}
    ${h.policy.remove&&!h.removed?`<p class="notice">${t("removing")}</p>`:""}
    ${h.removed||h.policy.remove?"":`<div class="actions">${button(h.policy.protect_hid?"hidOff":"hidOn",h.policy.protect_hid?"hid_off":"hid_on")}${h.local?"":button("remove","remove","danger")}</div>`}
    <div class="pills">${["devices","ports"].map(key=>`<button class="small" ${tab===key?'aria-current="true"':""} data-tab="${key}">${t(key)} · ${h[key]?.length??0}</button>`).join("")}<button class="small" ${tab==="events"?'aria-current="true"':""} data-tab="events">${t("hostEvents")}</button></div>
    ${tab==="events"?hostAuditTable():tab==="ports"?portRows(h):deviceRows(h)}`;
}

function auditRows(rows) {
  if (!rows.length) return blank("none");
  return `<div class="box scroll"><table><thead><tr>${["time","host","event","item","detail"].map(key=>`<th>${t(key)}</th>`).join("")}</tr></thead><tbody>
    ${rows.map(e=>`<tr><td>${esc(date(e.time))}</td><td>${esc(e.host||"Admin")}</td><td>${esc(t(e.kind))}</td><td>${esc(e.item||"—")}</td><td>${esc(e.detail||"—")}</td></tr>`).join("")}</tbody></table></div>`;
}

function hostAuditTable() {
  return `<div class="actions page-actions">${hostPage?button("latest","host-latest"):""}${hostBefore?button("older","host-older"):""}</div>${auditRows(hostEvents)}`;
}

function auditTable() {
  return `<div class="topline"><h1>${t("audit")}</h1><div class="actions">${auditPage?button("latest","latest"):""}${auditBefore?button("older","older"):""}</div></div>${auditRows(events)}`;
}

function renderData() {
  const content=document.getElementById("content");
  if (!content) return;
  const focused=content.contains(document.activeElement)?document.activeElement:null;
  const focusedData=focused?.tagName==="BUTTON" ? {...focused.dataset} : null;
  const oldScroll=content.querySelector(".scroll, .port-list");
  const scrollTop=oldScroll?.scrollTop||0, scrollLeft=oldScroll?.scrollLeft||0;
  const h=hosts.find(item=>item.id===selected);
  if (view==="audit") content.innerHTML=auditTable();
  else if (h) content.innerHTML=detail(h);
  else {
    const metrics=[["total",hosts.filter(h=>!h.removed).length],["online",hosts.filter(h=>hostStatus(h)==="online").length],
      ["blocked",hosts.reduce((sum,h)=>sum+(h.devices||[]).filter(d=>d.present&&d.blocked).length,0)]];
    content.innerHTML=`<div class="topline"><h1>${t(view)}</h1>${button("scan","scan","primary")}</div>
      ${view==="dashboard"?`<div class="hero"><div><h2>${t("overview")}</h2><p>${t("overviewText")}</p></div>${icon}</div>
      <div class="metrics">${metrics.map(([name,count])=>`<div class="metric">${t(name)}<strong>${count}</strong></div>`).join("")}</div>
      <div class="section-head"><h2>${t("computers")}</h2></div>`:""}${hostRows()}`;
  }
  const activity=document.getElementById("activity");
  const updatedScroll=content.querySelector(".scroll, .port-list");
  if (updatedScroll) { updatedScroll.scrollTop=scrollTop; updatedScroll.scrollLeft=scrollLeft; }
  if (focusedData) {
    const replacement=Array.from(content.querySelectorAll("button")).find(candidate=>
      Object.keys(focusedData).length>0 && Object.entries(focusedData).every(([key,value])=>candidate.dataset[key]===value));
    replacement?.focus({preventScroll:true});
  }
  const recent=h?hostEvents.slice(0,8):events.slice(0,8);
  activity.innerHTML=`<div class="section-head"><h2>${t("recent")}</h2></div><div class="box stream">${recent.length?recent.map(e=>
    `<div class="stream-row"><span class="stream-dot"></span><div><strong>${esc(t(e.kind))}</strong><small>${esc(e.item||e.host||"Admin")}</small><small>${esc(date(e.time))}</small></div></div>`).join(""):blank("none")}</div>`;
}

async function refresh() {
  if (refreshing || !auth?.authenticated) return;
  refreshing=true;
  try {
    const selectedAtRequest=selected;
    const [nextHosts,audit,hostAudit]=await Promise.all([api("dashboard"),api("audit"+(auditPage?`?before=${auditPage}`:"")),
      selectedAtRequest?api("audit?host="+encodeURIComponent(selectedAtRequest)+(hostPage?`&before=${hostPage}`:"")):Promise.resolve(null)]);
    hosts=nextHosts; events=audit.events; auditBefore=audit.before;
    if (selectedAtRequest===selected) {
      hostEvents=hostAudit?.events||[];
      hostBefore=hostAudit?.before||0;
      if (selected && !hosts.some(h=>h.id===selected)) { selected=""; tab="devices"; }
    }
    renderData();
  } catch(err) {
    if (err.message==="login") { dialog.close(); auth={authenticated:false}; render(); } else { notify(err.message); }
  } finally { refreshing=false; }
}

function openDialog(title,html) {
  dialog.innerHTML=`<div class="dialog-head"><h2 id="dialogTitle">${t(title)}</h2>${button("close","close","small")}</div>${html}`;
  if (!dialog.open) dialog.showModal();
}

function changePassword() {
  openDialog("changePassword", `<form id="changePasswordForm"><label>${t("currentPassword")}<input name="current" type="password" required maxlength="256" autocomplete="current-password"></label><label>${t("newPassword")}<input name="next" type="password" required minlength="12" maxlength="128" autocomplete="new-password"></label><label>${t("confirmPassword")}<input name="confirm" type="password" required minlength="12" maxlength="128" autocomplete="new-password"></label><p class="muted">${t("password_length")}</p><p class="error" id="changeError" aria-live="polite"></p><button class="primary">${uiIcon("save")}${t("save")}</button></form>`);
  document.getElementById("changePasswordForm").onsubmit=async ev=>{
    ev.preventDefault(); const form=ev.currentTarget; const data=new FormData(form); const send=form.querySelector("button");
    if(data.get("next")!==data.get("confirm")){document.getElementById("changeError").textContent=t("passwordMismatch");return;}
    send.disabled=true;
    try {const result=await api("auth/change",{Password:data.get("next"),CurrentPassword:data.get("current")});form.reset();showRecovery(result.recovery);}
    catch(err){const line=document.getElementById("changeError");if(line)line.textContent=t(err.message);}
    finally{send.disabled=false;}
  };
}

function showRecovery(key) {
  openDialog("recovery",`<p>${t("recoveryHelp")}</p><p class="code" id="recoveryKey">${esc(key)}</p>${button("copy","copy","primary")}`);
}

async function scan() {
  openDialog("found",`<p class="muted">${t("scanning")}</p>`);
  try {
    const rows=await api("scan",{});
    if (!dialog.open) return;
    openDialog("found", rows.length ? rows.map(row=>`<div class="candidate"><div><strong>${esc(row.name)}</strong><span class="host-id">${esc(row.ip)} · ${esc(date(row.expires))}</span></div><button class="primary" data-candidate="${esc(row.id)}">${uiIcon("computers")}${t("pair")}</button></div>`).join("")
      :`<p class="muted">${t("noAgents")}</p>`);
  } catch(err) { if (dialog.open) openDialog("found",`<p class="error">${esc(t(err.message))}</p>`); }
}

function pair(id) {
  openDialog("pair",`<form id="pairForm"><label>${t("otpLabel")}<input name="otp" required inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"></label>
    <p id="pairError" class="error" aria-live="polite"></p><button class="primary">${t("pair")}</button></form>`);
  document.getElementById("pairForm").onsubmit=async ev=>{
    ev.preventDefault();
    const form=ev.currentTarget;
    const send=form.querySelector("button");
    send.disabled=true;
    try {
      const response=await api("pair",{ID:id,OTP:new FormData(form).get("otp")});
      dialog.close(); selected=response.id; tab="devices"; view="computers";
      render(); await refresh(); notify("paired");
    } catch(err) {
      const line=document.getElementById("pairError");
      if (line) line.textContent=t(err.message);
    } finally { send.disabled=false; }
  };
}

async function setPolicy(action,device="") {
  try {
    const policy=await api("policy",{ID:selected,Device:device,Action:action});
    const h=hosts.find(h=>h.id===selected);
    if (h) h.policy=policy;
    renderData(); notify("applied");
  } catch(err) { notify(err.message); }
}

function confirmPolicy(action,title,description) {
  openDialog(title,`<p>${t(description)}</p><form id="confirmForm"><button class="primary">${t("confirm")}</button></form>`);
  document.getElementById("confirmForm").onsubmit=ev=>{ev.preventDefault(); dialog.close(); void setPolicy(action);};
}

document.addEventListener("click",async ev=>{
  const b=ev.target.closest("button");
  if (!b) return;
  if (b.dataset.host) { selected=b.dataset.host; tab="devices"; hostPage=0; hostBefore=0; hostEvents=[]; renderData(); await refresh(); return; }
  if (b.dataset.tab) { tab=b.dataset.tab; renderData(); return; }
  if (b.dataset.policy) { await setPolicy(b.dataset.policy,b.dataset.device); return; }
  if (b.dataset.candidate) { pair(b.dataset.candidate); return; }
  const action=b.dataset.action;
  if (action?.startsWith("nav-")) { view=action.slice(4); selected=""; query=""; render(); await refresh(); return; }
  switch(action) {
    case "change-password": changePassword(); break;
    case "close": dialog.close(); break;
    case "scan": await scan(); break;
    case "back": selected=""; renderData(); await refresh(); break;
    case "toggle-menu": menuHidden=!menuHidden; localStorage.setItem("hm_menu_hidden",menuHidden?"1":"0"); render(); break;
    case "toggle-activity": activityHidden=!activityHidden; localStorage.setItem("hm_activity_hidden",activityHidden?"1":"0"); render(); break;
    case "reset": resetting=!resetting; render(); break;
    case "copy":
      try { await navigator.clipboard.writeText(document.getElementById("recoveryKey").textContent); notify("copied"); } catch { /* Key remains selectable. */ }
      break;
    case "hid_on": confirmPolicy("hid_on","hidOn","hidExplain"); break;
    case "hid_off": await setPolicy("hid_off"); break;
    case "remove": confirmPolicy("remove","remove","removeExplain"); break;
    case "logout":
      await api("auth/logout",{}); auth={authenticated:false}; selected=""; hosts=[]; events=[]; render(); break;
    case "older": auditPage=auditBefore; b.blur(); await refresh(); break;
    case "latest": auditPage=0; b.blur(); await refresh(); break;
    case "host-older": hostPage=hostBefore; b.blur(); await refresh(); break;
    case "host-latest": hostPage=0; b.blur(); await refresh(); break;
  }
});

(async()=>{
  try { auth=await api("status"); } catch { notify("service"); }
  render();
  await refresh();
  setInterval(refresh,4500);
})();
