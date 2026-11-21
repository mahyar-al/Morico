# MORICOLAND (MORICO STYLE) — راهنمای استقرار، امنیت و درگاه پرداخت زرین‌پال

فروشگاه اینترنتی و آتلیه طراحی اختصاصی **MORICO STYLE** مبتنی بر Node.js (Express + TypeScript) و React/Vite.

---

## پیش‌نیازها و مدیریت پکیج (Lockfile)

- **نسخه‌ی Node.js**: حداقل **Node.js 22.x** (تطبیق‌یافته با `esbuild --target=node22` و cPanel Node.js App Manager)
- **مدیر پکیج واحد**: پروژه تنها از یک فایل lock استاندارد npm (`package-lock.json`) استفاده می‌کند. فایل `bun.lock` قدیمی برای جلوگیری از تداخل و سازگاری کامل با `npm ci` در سرورهای cPanel حذف شده است.

نصب وابستگی‌ها:

```bash
npm ci --legacy-peer-deps
```

*(به دلیل ناسازگاری نسخه‌ی `peerOptional` بین `vite@8.3.8` و `esbuild@^0.25.0` در `package.json`، هنگام نصب با npm استفاده از `--legacy-peer-deps` ضروری است.)*

---

## اجرای محلی (Development & Test)

1. فایل `.env` را از روی `.env.example` بسازید و مقادیر محلی را تنظیم کنید (در محیط توسعه `ZARINPAL_MODE=sandbox` باشد).
2. اجرای سرور توسعه:
   ```bash
   npm run dev
   ```
3. اجرای کنترل تایپ و تست‌های خودکار پرداخت و امنیت:
   ```bash
   npm run lint
   npm run test:payment
   npm run test:security
   ```

---

## متغیرهای محیطی ضروری در Production

تمام مقادیر زیر را در بخش **Environment Variables** پنل «Setup Node.js App» در cPanel (یا در فایل `.env` خارج از دسترس عمومی) تنظیم کنید و هرگز رمزها یا `ZARINPAL_MERCHANT_ID` را در گیت قرار ندهید:

| متغیر | توضیح | نمونه مقدار Production |
| --- | --- | --- |
| `NODE_ENV` | محیط اجرای Node | `production` |
| `PORT` | پورت سرور (معمولاً توسط Passenger تنظیم می‌شود) | `3000` |
| `APP_BASE_URL` | آدرس کامل HTTPS سایت برای Callback زرین‌پال | `https://moricoland.ir` |
| `ALLOWED_ORIGINS` | دامنه‌های مجاز CORS و CSRF Origin | `https://moricoland.ir,https://www.moricoland.ir` |
| `DATA_DIR` | مسیر ذخیره‌سازی داده‌ها (باید بیرون از پوشه اپ باشد) | `/home/USER/morico_data` |
| `UPLOADS_DIR` | مسیر آپلود تصاویر و فایل‌های طراحی (بیرون از پوشه اپ) | `/home/USER/morico_uploads` |
| `ADMIN_USERNAME` | نام کاربری پنل ادمین | `morico_admin` |
| `ADMIN_PASSWORD` | رمز عبور قوی ادمین | *(رشته قوی تصادفی)* |
| `SESSION_SECRET` | کلید امضای توکن‌های JOSE (حداقل ۳۲ کاراکتر) | *(خروجی `openssl rand -hex 32`)* |
| `REQUIRE_ADMIN_MFA` | اجباری بودن MFA ادمین در production | `true` |
| `ZARINPAL_MODE` | حالت درگاه (`sandbox` یا `production`) | `production` |
| `ZARINPAL_MERCHANT_ID` | مرچنت آیدی UUID ۳۶ کاراکتری زرین‌پال | *(UUID واقعی پذیرنده)* |
| `ZARINPAL_CALLBACK_URL` | آدرس ثابت HTTPS بازگشت بانکی | `https://moricoland.ir/api/payments/zarinpal/callback` |
| `REDIS_URL` | اختیاری — برای Redis در Rate Limit / Revocation | *(اختیاری)* |

> **قواعد ایمنی Fail-Fast در زمان راه‌اندازی (`production`)**:
> - اگر `NODE_ENV !== 'production'` باشد و `ZARINPAL_MODE=production` تنظیم شود، سرور بالا نمی‌آید.
> - اگر `ZARINPAL_CALLBACK_URL` یا `APP_BASE_URL` در محیط `production` غیرـHTTPS باشد یا ست نشود، درگاه یا سرور Fail-Fast می‌شود (هیچ اتکایی به هدر `Host` وجود ندارد).

---

## راهنمای استقرار روی cPanel (Setup Node.js App / Passenger)

1. **محدودیت حیاتی تک‌فرآیندی (Single Instance Only)**:
   از آنجا که ذخیره‌سازی فعلی روی فایل JSON (`store.json`) و قفل‌های درون‌حافظه‌ای (`withOrderLock`) انجام می‌شود، برنامه **حتماً باید روی ۱ instance / 1 worker** در Passenger اجرا شود (عدم استفاده از Cluster Mode چندفرآیندی).
   *(در صورت رشد چشمگیر تعداد سفارش‌ها، مهاجرت به SQLite/MySQL پیشنهاد می‌شود.)*

2. **مسیر پایدار داده خارج از پوشه‌ی برنامه (`DATA_DIR` / `UPLOADS_DIR`)**:
   پوشه‌های `/home/USER/morico_data` و `/home/USER/morico_uploads` را خارج از ریشه‌ی کد اپ ایجاد کنید تا با استقرار یا آپلود نسخه‌های جدید کد، فایل‌های `store.json` و تصاویر طراحی سفارشی مشتریان بازنویسی نشوند.

3. **بیلد و راه‌اندازی**:
   - در cPanel Node.js App:
     - **Node.js Version**: `22.x`
     - **Application Mode**: `Production`
     - **Application Startup File**: `app.cjs` (متغیر `NODE_ENV=production` را تنظیم کرده و `./dist/server.js` را اجرا می‌کند)
   - اجرای نصب و بیلد:
     ```bash
     npm ci --omit=dev --legacy-peer-deps
     npm run build
     ```
     *(دستور `npm run build` باندل کلاینت را در `dist/` و باندل سرور ESM را در `dist/server.js` می‌سازد و فایل‌های نمونه/تست `uploads` و `assets/aistudio` را از خروجی `dist/` حذف می‌کند.)*
   - در نهایت در پنل Node.js App روی **Restart** کلیک کنید.

4. **پایش سلامت سرویس (`Health Check`)**:
   پس از راه‌اندازی، مسیر زیر باید وضعیت `200 OK` برگرداند (بدون افشای هیچ کلید محرمانه یا Merchant ID):
   ```text
   GET https://YOUR_DOMAIN/api/health
   ```

5. **بکاپ روزانه‌ی خودکار در cPanel (Cron Jobs)**:
   اسکریپت `scripts/backup-data.sh` آماده شده و ۳۰ بکاپ آخر را نگه می‌دارد:
   ```bash
   chmod +x scripts/backup-data.sh
   ```
   نمونه Cron Job روزانه (ساعت ۳:۰۰ بامداد):
   ```cron
   0 3 * * * DATA_DIR=/home/USER/morico_data UPLOADS_DIR=/home/USER/morico_uploads BACKUP_DIR=/home/USER/morico_backups /home/USER/app/scripts/backup-data.sh >> /home/USER/morico_backups/backup.log 2>&1
   ```
   توصیه می‌شود خروجی پوشه‌ی `BACKUP_DIR` به‌صورت دوره‌ای به فضای خارج از هاست نیز منتقل شود.

---

## چک‌لیست نهایی پیش از خروج از Sandbox و اتصال به درگاه واقعی زرین‌پال

### ۱. آزمون در محیط `ZARINPAL_MODE=sandbox`
- یک پرداخت موفق کامل از سبد خرید تا صفحه رسید و بررسی ثبت `refId` و کسر دقیق موجودی در پنل ادمین.
- یک پرداخت ناموفق / لغو در درگاه (دکمه انصراف) و اطمینان از عدم کسر موجودی و نمایش صحیح وضعیت به کاربر.
- تست verify تکراری (کد `101` زرین‌پال) و شبیه‌سازی قطع شبکه در verify (وضعیت `PENDING_VERIFY` و بازیابی خودکار ۵ دقیقه‌ای توسط reconciler).
- تست تبدیل واحد: سفارش `۱٬۰۰۰` تومانی باید دقیقاً `۱۰٬۰۰۰` ریال به زرین‌پال ارسال کند و سفارش بالای `۱٬۵۰۰٬۰۰۰` تومان هزینه ارسال رایگان داشته باشد.

### ۲. تنظیمات سرور و شبکه
- SSL (گواهی HTTPS) فعال باشد و تمام ترافیک `http://` به `https://` ریدایرکت شود.
- ارتباط خروجی سرور هاست با `https://payment.zarinpal.com/pg/v4/payment/request.json` و `verify.json` برقرار و بدون محدودیت فایروال باشد.

### ۳. پنل پذیرندگان زرین‌پال و الزامات سایت
- دامنه‌ی اصلی سایت در پنل زرین‌پال تأیید شده و `Merchant ID` فعال و متعلق به همین دامنه باشد.
- دامنه‌ی `ZARINPAL_CALLBACK_URL` دقیقاً با دامنه‌ی تأییدشده در زرین‌پال یکی باشد.
- صفحات قوانین و مقررات، رویه‌ی بازگشت کالا، اطلاعات تماس با ما و نماد اعتماد الکترونیک (در صورت الزام) در سایت دسترس‌پذیر و کامل باشند.
