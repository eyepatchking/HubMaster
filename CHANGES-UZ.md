# HubMaster 2.3.0

Tuzatildi va qo‘shildi:
- Joriy parol orqali parol almashtirish; yangi parolni ikki marta kiritish.
- Eski sessiyalar va recovery kalitini bekor qilish.
- Parol ham, recovery kaliti ham yo‘qolganda Windows administrator ruxsati bilan tiklash. Start menyusida HubMaster Admin Recovery yorlig‘i.
- Masofadagi Admin ishlamasa, mahalliy Windows administratori yoki Linux root orqali qurilma bloklarini yechib agentni o‘chirish.
- Auditni yuklab olish, 16 MiB bo‘laklarga arxivlash, yozish xatolarida holatni saqlash va tugallanmagan oxirgi yozuvni dalili bilan tiklash.
- Buzilgan offline navbat faylini alohida saqlab, qolgan navbatni davom ettirish.
- Linux’da rename hodisalarini juftlash, watcher qayta ishga tushishi, auditd orqali jarayon nomi va PID.
- Linux USB/USB-C/SD/optik qurilma inventari va qo‘llab-quvvatlangan drayverlarda qayta tiklanadigan bloklash.
- Tizim diski, papka ruxsatlari, parallel pairing va katta inventar uchun qo‘shimcha tekshiruvlar.
- Dark/Light/System, xatolarni ko‘rsatish va mavjud bo‘lmagan boshqaruvlar uchun aniq izoh.

Yangilash:
Eski papkalarni o‘chirmasdan yangi Setup faylini ishga tushiring. So‘ng parol unutilgan bo‘lsa Start → HubMaster Admin Recovery.

Ochiq chegaralar:
Polling yangi HID’ning birinchi harakatini to‘xtatishini kafolatlamaydi. USB-C jismoniy port xaritasi firmware ma’lumotiga bog‘liq. Linux runtime, auditd va haqiqiy qurilmalarda yangi boshqaruvlar bu Windows muhitida sinalmagan. Sertifikat bo‘lmagani uchun EXE imzosiz. Audit va offline navbat limitlari bor; disk uzoq vaqt to‘lsa audit yo‘qotilishi mumkin va audit.gap qayd etiladi. Bu chegaralar README.md da yozilgan.
