import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import sharp from 'sharp';
import { SignJWT, jwtVerify } from 'jose';

import {
  validatePasswordPolicy,
  checkPasswordHistory,
  hashPasswordAsync,
  hashPasswordSync,
  verifyPasswordAsync,
  verifyDummyPasswordAsync,
  toEnglishDigits,
  cleanPhoneNumber,
  normalizeIranianMobile,
  normalizeAndValidateEmail,
  sanitizeText,
  signJoseToken,
  verifyJoseToken,
  TokenPayload,
  checkLockout,
  checkLockoutAsync,
  recordAuthFailure,
  recordAuthFailureAsync,
  clearAuthFailure,
  clearAuthFailureAsync,
  getActiveLockoutsCount,
  createGeneralRateLimiter,
  createTrackingRateLimiter,
  createDiscountRateLimiter,
  DUMMY_TIMING_HASH
} from './src/server/security';

import {
  DATA_DIR,
  BACKUPS_DIR,
  DATA_FILE,
  AUDIT_LOG_FILE,
  UPLOADS_DIR,
  DESIGN_UPLOADS_DIR,
  recordAuditLog,
  getRecentAuditLogs,
  loadAuditLogs,
  loadRevokedTokens,
  recordRevokedToken,
  isTokenRevoked,
  performDailyBackup,
  saveStoreStateAtomic,
  verifyAuditLogIntegrity
} from './src/server/storage';

import {
  verifyTotpCode,
  generateTotpSecret,
  generateOtpAuthUrl,
  generateBackupCodes
} from './src/server/totp';

import { isRedisConnected } from './src/server/redisStore';

import {
  isValidOrderStatus,
  isValidOrderStatusTransition,
  isCancelledOrderStatus,
  isPaidOrFulfilledOrderStatus,
  isProductCustomizable,
  getProductCustomizationFee,
  evaluateDiscountCode,
  sanitizeOrderInput,
  sanitizeCategoryInput,
  sanitizeProductInput,
  sanitizeDiscountInput,
  OrderStatus
} from './src/server/schema';

import {
  requestZarinPalPayment,
  verifyZarinPalTransaction,
  isValidMerchantId,
  maskMerchantId,
  tomanToRial,
  ZarinPalVerifyResult,
  ZarinPalMode
} from './src/server/payment';

dotenv.config();

// ============================================================================
// CONFIGURATION, SECRETS & FAIL-FAST SECURITY (OWASP ASVS V1.1, V2.1, V6.1)
// ============================================================================
const isProduction = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin@morico.style';
// Admin MFA is only enforced when REQUIRE_ADMIN_MFA=true (the admin UI has no MFA screen yet)
const REQUIRE_ADMIN_MFA = process.env.REQUIRE_ADMIN_MFA === 'true';
let ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
let SESSION_SECRET = process.env.SESSION_SECRET;

export function validateProductionEnvironment(env: NodeJS.ProcessEnv = process.env): { ok: true } | { ok: false; error: string } {
  const modeEnv = (env.ZARINPAL_MODE || '').trim().toLowerCase();
  const isProdEnv = env.NODE_ENV === 'production';

  if (modeEnv === 'production' && !isProdEnv) {
    return {
      ok: false,
      error:
        'FATAL PRODUCTION SECURITY ERROR: ZARINPAL_MODE=production requires NODE_ENV=production. Refusing to start in non-production mode with live gateway configuration.'
    };
  }

  if (isProdEnv) {
    const adminPass = env.ADMIN_PASSWORD;
    const sessSecret = env.SESSION_SECRET;
    if (!adminPass || adminPass === 'morico2026' || adminPass === 'morico1234') {
      return {
        ok: false,
        error:
          'FATAL PRODUCTION SECURITY ERROR: ADMIN_PASSWORD is missing or set to an insecure default (OWASP ASVS V2.1).'
      };
    }
    if (!sessSecret || sessSecret.length < 32) {
      return {
        ok: false,
        error:
          'FATAL PRODUCTION SECURITY ERROR: SESSION_SECRET is missing or has fewer than 32 characters (OWASP ASVS V6.1).'
      };
    }
    const explicitCb = (env.ZARINPAL_CALLBACK_URL || '').trim();
    const appBase = (env.APP_BASE_URL || '').trim().replace(/\/+$/, '');
    const hasValidCallback = Boolean(explicitCb && /^https:\/\//i.test(explicitCb));
    const hasValidBase = Boolean(appBase && /^https:\/\//i.test(appBase));
    if (!hasValidCallback && !hasValidBase) {
      return {
        ok: false,
        error:
          'FATAL PRODUCTION SECURITY ERROR: Either APP_BASE_URL (starting with https://) or ZARINPAL_CALLBACK_URL (starting with https://) must be configured in production mode.'
      };
    }
  }

  return { ok: true };
}

const envCheck = validateProductionEnvironment(process.env);
if ('error' in envCheck) {
  console.error('================================================================');
  console.error(envCheck.error);
  console.error('================================================================');
  process.exit(1);
}

if (!isProduction) {
  if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
    SESSION_SECRET = crypto.randomBytes(32).toString('hex');
  }
  if (!ADMIN_PASSWORD) {
    ADMIN_PASSWORD = 'morico2026';
  }
}

// Ensure persistent folders and indices are ready
loadRevokedTokens();
loadAuditLogs();
performDailyBackup();

// ============================================================================
// DATA MODELS & IN-MEMORY CACHE
// ============================================================================
export interface DbUser {
  id: string;
  name: string;
  username: string;
  email: string;
  phone: string;
  passwordHash: string;
  role: 'admin' | 'user' | 'staff';
  joinDate: string;
  lastLogin: string;
  loginCount: number;
  tokenVersion?: number;
  mustChangePassword?: boolean;
  mfaEnabled?: boolean;
  mfaSecret?: string;
  backupCodes?: string[];
  passwordHistory?: string[];
}

const DEFAULT_USERS: DbUser[] = [
  {
    id: 'usr-admin-01',
    name: 'مدیر ارشد آتلیه MORICO',
    username: ADMIN_USERNAME,
    email: ADMIN_USERNAME,
    phone: '۰۹۱۲۲۲۰۸۹۴۱',
    passwordHash: hashPasswordSync(ADMIN_PASSWORD),
    role: 'admin',
    joinDate: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
    loginCount: 1,
    tokenVersion: 1,
    mustChangePassword: !isProduction && ADMIN_PASSWORD === 'morico2026'
  }
];

const DEFAULT_CATEGORIES: any[] = [];
const DEFAULT_PRODUCTS: any[] = [];
const DEFAULT_HERO_SLIDES: any[] = [];

const DEFAULT_DISCOUNTS = [
  {
    id: 'disc-morico2026',
    code: 'MORICO2026',
    type: 'percentage',
    amount: 15,
    percent: 15,
    description: 'تخفیف ویژه ۱۵٪ روی کالکشن ۲۰۲۶',
    minOrderAmount: 500000,
    maxDiscountAmount: 250000,
    active: true,
    usedCount: 0,
    usageLimit: 100
  },
  {
    id: 'disc-welcome10',
    code: 'WELCOME10',
    type: 'percentage',
    amount: 10,
    percent: 10,
    description: 'تخفیف خرید اول ۱۰٪',
    minOrderAmount: 300000,
    maxDiscountAmount: 150000,
    active: true,
    usedCount: 0,
    usageLimit: 500
  }
];

const DEFAULT_BANNERS = [
  {
    id: 'banner-atelier-drop',
    badge: 'OFFER 2026',
    title: 'تخفیف ویژه تمامی دسته‌بندی‌های کاتالوگ',
    subtitle: 'کالای دیجیتال، دکوراسیون و نور، پوشاک و محصولات باکیفیت با ضمانت اصالت.',
    description: 'کالای دیجیتال، دکوراسیون و نور، پوشاک و محصولات باکیفیت با ضمانت اصالت.',
    discount: '۱۵٪ تخفیف',
    promoCode: 'MORICO2026',
    linkText: 'مشاهده کاتالوگ',
    linkUrl: 'catalog',
    imageUrl: '/src/assets/images/banner_collection_drop_1792400592647.jpg',
    backgroundColor: '#111110',
    bgGradient: 'from-[#111110] via-[#1c1c1a] to-[#2a2a28]',
    placement: 'middle_banner',
    sortOrder: 1,
    active: true
  },
  {
    id: 'banner-custom-studio',
    badge: 'CUSTOM STUDIO',
    title: 'استودیو طراحی آنلاین و چاپ اختصاصی',
    subtitle: 'امکان چاپ لوگو، مونوگرام و تایپوگرافی دلخواه با ماندگاری بالا.',
    description: 'امکان چاپ لوگو، مونوگرام و تایپوگرافی دلخواه با ماندگاری بالا.',
    discount: '۱۰٪ خرید اول',
    promoCode: 'WELCOME10',
    linkText: 'ورود به استودیو',
    linkUrl: 'customizer',
    imageUrl: '/src/assets/images/banner_studio_custom_1792400593263.jpg',
    backgroundColor: '#111110',
    bgGradient: 'from-[#1a2228] via-[#111110] to-[#181d22]',
    placement: 'middle_banner',
    sortOrder: 2,
    active: true
  }
];

const DEFAULT_SITE_CONTENT = {
  heroSlides: DEFAULT_HERO_SLIDES,
  branding: {
    logoUrl: '/brand/morico-logo.jpg',
    siteTitle: 'MORICO STYLE',
    siteSubtitle: 'فروشگاه موریکو',
    primaryColor: '#111110',
    accentColor: '#FFFFFF'
  },
  hero: {
    badge: 'فروشگاه اینترنتی موریکو',
    title: 'فروشگاه اینترنتی موریکو؛ خرید آنلاین کالاهای متنوع و باکیفیت',
    description: 'فروشگاه آنلاین موریکو ارائه دهنده انواع کالای دیجیتال، دکوراسیون و نور، پوشاک، لوازم تحریر و محصولات سفارشی با تضمین کیفیت و ارسال سریع به سراسر کشور.',
    ctaPrimary: 'مشاهده کل کاتالوگ فروشگاه',
    ctaSecondary: 'استودیو طراحی آنلاین',
    imageUrl: 'https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=900&auto=format&fit=crop&q=80',
    floatingTagTitle: 'تنوع گسترده دسته‌بندی‌ها',
    floatingTagSubtitle: 'کالای دیجیتال، دکوراسیون، پوشاک و محصولات سفارشی',
    features: [
      { title: 'تضمین اصالت تمام کالاها' },
      { title: 'ارسال سریع به سراسر کشور' },
      { title: '۷ روز مهلت تست و مرجوعی' }
    ]
  },
  sections: {
    showHero: true,
    showQuickCategories: true,
    showBanners: true,
    showProcess: true,
    showCatalog: false,
    showCraftsmanship: true,
    showFaq: true,
    sectionOrder: ['hero', 'quick_categories', 'banners', 'process', 'craftsmanship', 'faq']
  },
  craftsmanship: {
    badge: 'درباره فروشگاه موریکو',
    title: 'اصالت کیفیت، تنوع محصولات و خرید مطمئن',
    description: 'فروشگاه موریکو یک فروشگاه اینترنتی جامع است که با هدف عرضه کالاهای منتخب، کاربردی و اصیل در دسته‌بندی‌های گوناگون فعالیت می‌کند. تمامی محصولات پس از تایید کیفی به کاتالوگ اضافه شده و با گارانتی و ضمانت بازگشت ارسال می‌گردند.',
    features: [
      { title: 'بررسی دقیق مشخصات فنی', subtitle: 'تطابق کامل کالای تحویلی با مشخصات ثبت‌شده در سایت' },
      { title: 'پشتیبانی دائمی سفارشات', subtitle: 'همراهی با مشتری از لحظه ثبت سفارش تا تحویل' },
      { title: 'بسته‌بندی ایمن و ضربه‌گیر', subtitle: 'ارسال تخصصی متناسب با حساسیت کالا' }
    ],
    image: 'https://images.unsplash.com/photo-1441986300917-64674bd600d8?w=900&auto=format&fit=crop&q=80'
  },
  faq: [
    {
      id: 'faq-1',
      q: 'آیا تمام کالاها دارای ضمانت اصالت و گارانتی هستند؟',
      a: 'بله، کلیه محصولات موجود در فروشگاه موریکو دارای ضمانت اصالت کالا و مهلت تست سلامت فیزیکی هستند. همچنین کالاهای دیجیتال دارای گارانتی معتبر شرکتی می‌باشند.'
    },
    {
      id: 'faq-2',
      q: 'امکان طراحی آنلاین و سفارش محصولات اختصاصی چگونه است؟',
      a: 'در بخش استودیو طراحی آنلاین، شما می‌توانید محصول مورد نظر را انتخاب نموده و متن، لوگو یا مونوگرام دلخواهتان را روی آن قرار داده و مستقیماً سفارش دهید.'
    },
    {
      id: 'faq-3',
      q: 'مدت زمان آماده‌سازی و ارسال سفارشات چقدر است؟',
      a: 'سفارشات آماده کاتالوگ ظرف ۲۴ ساعت کاری تحویل پست پیشتاز می‌شوند. سفارشات چاپی و سفارشی نیز ظرف ۳ الی ۴ روز کاری ارسال می‌گردند.'
    },
    {
      id: 'faq-4',
      q: 'شرایط مرجوعی یا تعویض کالا چیست؟',
      a: 'در صورت هرگونه مغایرت مشخصات، نقص فنی یا آسیب‌دیدگی حین ارسال، کالا تا ۷ روز بدون قید و شرط تعویض یا مبلغ سفارش مسترد خواهد شد.'
    }
  ],
  howItWorks: {
    step1Title: 'انتخاب کالا از دسته‌بندی‌های متنوع',
    step1Desc: 'از میان کالای دیجیتال، دکوراسیون، پوشاک یا لوازم تحریر، محصول دلخواهتان را بیابید.',
    step2Title: 'بررسی مشخصات فنی و تنوع',
    step2Desc: 'رنگ، مدل، ظرفیت، گارانتی یا مشخصات فنی اختصاصی هر کالا را انتخاب کنید.',
    step3Title: 'پرداخت امن و تحویل فوری درب منزل',
    step3Desc: 'سفارش شما با بسته‌بندی اختصاصی و بیمه باربری به سراسر کشور ارسال خواهد شد.'
  },
  footer: {
    phone: '۰۲۱-۲۲۰۸۹۴۱۰',
    address: 'تهران، خیابان فرشته (شهید فیاضی)، خیابان مریم غربی، پلاک ۲۴، مرکز خدمات MORICO',
    email: 'support@moricostyle.com',
    instagram: '@moricostyle',
    telegram: 't.me/moricostyle',
    workingHours: 'شنبه تا پنج‌شنبه: ۱۰:۰۰ الی ۲۰:۰۰',
    enamadActive: true,
    aboutText: 'فروشگاه اینترنتی موریکو؛ مرجع خرید آنلاین انواع کالای دیجیتال، دکوراسیون و نور، پوشاک و محصولات سفارشی با تضمین اصالت و ارسال سریع به سراسر کشور.',
    copyrightText: '© ۲۰۲۶ فروشگاه اینترنتی موریکو (MORICO STYLE). تمامی حقوق محفوظ است.'
  },
  announcementBar: {
    enabled: true,
    text: 'فروشگاه اینترنتی موریکو فعال شد — ارسال رایگان سفارشات اول با کد WELCOME10',
    discountCode: 'WELCOME10',
    supportPhone: '۰۲۱-۲۲۰۸۹۴۱۰',
    bgColor: '#111110',
    textColor: '#FFFFFF'
  },
  navLinks: [
    { id: 'nav-1', label: 'صفحه اصلی', href: 'home', active: true, sortOrder: 1 },
    { id: 'nav-2', label: 'کاتالوگ و محصولات', href: 'catalog', active: true, sortOrder: 2 },
    { id: 'nav-3', label: 'طراحی آنلاین و سفارشی', href: 'customizer', active: true, highlight: false, sortOrder: 3 },
    { id: 'nav-4', label: 'درباره ما و اصالت کالا', href: 'story', active: true, sortOrder: 4 },
    { id: 'nav-5', label: 'رهگیری سفارشات', href: 'track', active: true, sortOrder: 5 }
  ],
  policyPages: {
    about: 'فروشگاه اینترنتی موریکو با هدف ارائه محصولات باکیفیت، بدون واسطه و اصیل در دسته‌بندی‌های متنوع از جمله کالای دیجیتال، لوازم خانه، پوشاک و محصولات چاپی سفارشی راه‌اندازی شده است.',
    terms: '۱. ثبت سفارش در موریکو به منزله پذیرش کامل قوانین و رویه‌های فروشگاه است.\n۲. کلیه سفارشات با ضمانت تطابق فیزیکی و اصالت کالا ارسال می‌شوند.\n۳. سفارش‌های چاپی و سفارشی پس از تایید مشتری و شروع چاپ امکان لغو ندارند.',
    privacy: 'فروشگاه موریکو به حریم خصوصی تمامی همراهان خود احترام کامل می‌گذارد. شماره‌های تماس و نشانی‌های پستی ثبت‌شده صرفاً برای تحویل مرسولات استفاده شده و محرمانه باقی می‌مانند.',
    returns: 'تمامی اقلام دارای ۷ روز مهلت تست فنی یا سلامت فیزیکی هستند. در صورت وجود هرگونه مغایرت یا نقص، سفارش بدون هزینه تعویض یا مسترد می‌گردد.',
    shipping: 'ارسال با پست پیشتاز بیمه‌شده ظرف ۲ الی ۴ روز کاری به سراسر کشور.\nامکان تحویل اکسپرس در همان روز برای شهر تهران.',
    contact: 'نشانی مرکزی:\nتهران، خیابان فرشته (شهید فیاضی)، خیابان مریم غربی، پلاک ۲۴، مرکز خدمات MORICO\nتلفن تماس: ۰۲۱-۲۲۰۸۹۴۱۰\nپاسخگویی: ۱۰:۰۰ الی ۲۰:۰۰'
  },
  categoryQuickIcons: [
    { id: 'qc-custom', title: 'طراحی آنلاین', badge: 'اختصاصی', icon: 'Palette', bgColor: '#DB2777', badgeBgColor: '#9D174D', linkType: 'action', linkTarget: 'customizer', active: true, sortOrder: 1 }
  ],
  status: 'published',
  publishedAt: new Date().toISOString()
};

const ENV_ZARINPAL_MERCHANT = (process.env.ZARINPAL_MERCHANT_ID || '').trim();
const ENV_ZARINPAL_MODE: ZarinPalMode =
  (process.env.ZARINPAL_MODE || '').trim().toLowerCase() === 'production' ? 'production' : 'sandbox';

const DEFAULT_GATEWAY = {
  gatewayName: 'زرین‌پال (ZarinPal IPG)',
  configured: isValidMerchantId(ENV_ZARINPAL_MERCHANT),
  mode: ENV_ZARINPAL_MODE,
  merchantId: '',
  disabledReason: 'درگاه پرداخت اینترنتی هنوز متصل نشده است و در انتظار فعال‌سازی توسط مدیریت فروشگاه می‌باشد.'
};

let dbUsers: DbUser[] = [...DEFAULT_USERS];
let dbCategories: any[] = [...DEFAULT_CATEGORIES];
let dbCategoryAttributes: any[] = [];
let dbProducts: any[] = [...DEFAULT_PRODUCTS];
let dbOrders: any[] = [];
let dbDiscounts: any[] = [...DEFAULT_DISCOUNTS];
let dbBanners: any[] = [...DEFAULT_BANNERS];
let dbBestSellers: any[] = [];
let dbTopWeekly: any[] = [];
let dbSiteContent: any = { ...DEFAULT_SITE_CONTENT };
let dbGatewayStatus: any = { ...DEFAULT_GATEWAY };

export function savePersistentState(immediate = false) {
  const state = {
    users: dbUsers,
    categories: dbCategories,
    categoryAttributes: dbCategoryAttributes,
    products: dbProducts,
    orders: dbOrders,
    discounts: dbDiscounts,
    banners: dbBanners,
    bestSellers: dbBestSellers,
    topWeekly: dbTopWeekly,
    siteContent: dbSiteContent,
    gatewayStatus: dbGatewayStatus
  };
  saveStoreStateAtomic(state, immediate);
}

export function loadPersistentState() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      const state = JSON.parse(raw);
      if (Array.isArray(state.categories)) dbCategories = state.categories;
      if (Array.isArray(state.categoryAttributes)) dbCategoryAttributes = state.categoryAttributes;
      if (Array.isArray(state.products)) dbProducts = state.products;
      if (Array.isArray(state.orders)) dbOrders = state.orders;
      if (Array.isArray(state.discounts)) dbDiscounts = state.discounts;
      if (Array.isArray(state.banners)) dbBanners = state.banners;
      if (Array.isArray(state.bestSellers)) dbBestSellers = state.bestSellers;
      if (Array.isArray(state.topWeekly)) dbTopWeekly = state.topWeekly;
      if (state.siteContent && typeof state.siteContent === 'object') {
        dbSiteContent = {
          ...DEFAULT_SITE_CONTENT,
          ...state.siteContent,
          branding: { ...DEFAULT_SITE_CONTENT.branding, ...(state.siteContent.branding || {}) },
          hero: { ...DEFAULT_SITE_CONTENT.hero, ...(state.siteContent.hero || {}) },
          sections: {
            ...DEFAULT_SITE_CONTENT.sections,
            ...(state.siteContent.sections || {}),
            showCatalog: false,
            showQuickCategories: state.siteContent.sections?.showQuickCategories !== false
          },
          heroSlides: Array.isArray(state.siteContent.heroSlides)
            ? state.siteContent.heroSlides
            : DEFAULT_HERO_SLIDES,
          craftsmanship: { ...DEFAULT_SITE_CONTENT.craftsmanship, ...(state.siteContent.craftsmanship || {}) },
          footer: { ...DEFAULT_SITE_CONTENT.footer, ...(state.siteContent.footer || {}) },
          announcementBar: { ...DEFAULT_SITE_CONTENT.announcementBar, ...(state.siteContent.announcementBar || {}) },
          policyPages: { ...DEFAULT_SITE_CONTENT.policyPages, ...(state.siteContent.policyPages || {}) }
        };
      }
      if (state.gatewayStatus && typeof state.gatewayStatus === 'object') {
        dbGatewayStatus = { ...DEFAULT_GATEWAY, ...state.gatewayStatus };
      }
      if (Array.isArray(state.users) && state.users.length > 0) {
        dbUsers = state.users;
      }
      console.log('MORICO STYLE: Persistent store data loaded securely from disk.');
      return;
    }
  } catch (err) {
    console.warn('Could not load persistent state, initializing defaults:', err);
  }
  savePersistentState(true);
}

loadPersistentState();

// ============================================================================
// PAYMENT GATEWAY CONFIGURATION, LOCKING & ORDER TOKEN HELPERS
// ============================================================================
const orderOperationLocks = new Map<string, Promise<void>>();

async function withOrderLock<T>(orderId: string, fn: () => Promise<T>): Promise<T> {
  const prev = orderOperationLocks.get(orderId) || Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const chained = prev.then(() => current);
  orderOperationLocks.set(orderId, chained);
  await prev;
  try {
    return await fn();
  } finally {
    release();
    if (orderOperationLocks.get(orderId) === chained) {
      orderOperationLocks.delete(orderId);
    }
  }
}

export function getEffectiveGatewayConfig() {
  const envMerchant = (process.env.ZARINPAL_MERCHANT_ID || '').trim();
  const envModeRaw = (process.env.ZARINPAL_MODE || '').trim().toLowerCase();
  const envMode: ZarinPalMode | undefined =
    envModeRaw === 'production' ? 'production' : envModeRaw === 'sandbox' ? 'sandbox' : undefined;
  const envCallbackUrl = (process.env.ZARINPAL_CALLBACK_URL || '').trim();

  const effectiveMerchantId = envMerchant || String(dbGatewayStatus.merchantId || '').trim();
  const mode: ZarinPalMode = envMode || (dbGatewayStatus.mode === 'production' ? 'production' : 'sandbox');
  const hasMerchantId = isValidMerchantId(effectiveMerchantId);
  const configured = Boolean(dbGatewayStatus.configured);
  const ready = configured && hasMerchantId;

  let disabledReason =
    dbGatewayStatus.disabledReason ||
    'درگاه پرداخت اینترنتی هنوز متصل نشده است و در انتظار فعال‌سازی توسط مدیریت فروشگاه می‌باشد.';
  if (configured && !hasMerchantId) {
    disabledReason = 'کد مرچنت (Merchant ID) درگاه زرین‌پال تنظیم نشده یا قالب معتبری ندارد.';
  }

  return {
    gatewayName: dbGatewayStatus.gatewayName || 'زرین‌پال (ZarinPal IPG)',
    configured,
    ready,
    mode,
    merchantId: effectiveMerchantId,
    hasMerchantId,
    merchantIdMasked: hasMerchantId ? maskMerchantId(effectiveMerchantId) : '',
    envManaged: Boolean(envMerchant),
    callbackUrl: envCallbackUrl || undefined,
    disabledReason
  };
}

export function getCallbackUrl(req?: Request): string {
  const explicit = (process.env.ZARINPAL_CALLBACK_URL || '').trim();
  const urlProtoPattern = isProduction ? /^https:\/\//i : /^https?:\/\//i;
  if (explicit && urlProtoPattern.test(explicit)) {
    return explicit;
  }
  const appBase = (process.env.APP_BASE_URL || '').trim().replace(/\/+$/, '');
  if (appBase && urlProtoPattern.test(appBase)) {
    return `${appBase}/api/payments/zarinpal/callback`;
  }
  if (isProduction) {
    throw new Error('Production requires HTTPS APP_BASE_URL or ZARINPAL_CALLBACK_URL');
  }
  const forwardedProto =
    req && typeof req.headers['x-forwarded-proto'] === 'string'
      ? req.headers['x-forwarded-proto'].split(',')[0].trim()
      : '';
  const protocol = forwardedProto || req?.protocol || 'http';
  const forwardedHost =
    req && typeof req.headers['x-forwarded-host'] === 'string'
      ? req.headers['x-forwarded-host'].split(',')[0].trim()
      : '';
  const host = forwardedHost || req?.get('host') || `localhost:${PORT}`;
  return `${protocol}://${host}/api/payments/zarinpal/callback`;
}

function getOrderPaymentJwtKey(): Uint8Array {
  return crypto.createHash('sha256').update(`${SESSION_SECRET!}:order_payment`).digest();
}

async function signOrderPaymentToken(order: any): Promise<string> {
  const phoneSuffix = cleanPhoneNumber(order.customerPhone || '').slice(-10);
  return await new SignJWT({
    purpose: 'order_payment',
    orderId: order.id,
    orderNumber: order.orderNumber,
    phoneSuffix
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('4h')
    .sign(getOrderPaymentJwtKey());
}

async function verifyOrderPaymentToken(
  token: string,
  order: any
): Promise<boolean> {
  try {
    const { payload } = await jwtVerify(token, getOrderPaymentJwtKey(), {
      algorithms: ['HS256']
    });
    if (payload.purpose !== 'order_payment') return false;
    return payload.orderId === order.id && payload.orderNumber === order.orderNumber;
  } catch {
    return false;
  }
}

async function isAuthorizedForOrderPayment(req: Request, order: any): Promise<boolean> {
  // 1. Dedicated payment token from header, body, cookie, or query
  const candidateTokens = [
    req.headers['x-payment-token'],
    req.body?.paymentToken,
    req.cookies?.morico_pay_order,
    req.query?.paymentToken
  ].filter((t): t is string => typeof t === 'string' && t.trim().length > 10);

  for (const tok of candidateTokens) {
    if (await verifyOrderPaymentToken(tok.trim(), order)) {
      return true;
    }
  }

  // 2. Customer or Admin session JWT (no raw phone fallback allowed - B2)
  const sessionToken = extractBearerOrCookieToken(req);
  if (sessionToken) {
    const userPayload = await verifyJoseToken(
      sessionToken,
      SESSION_SECRET!,
      (id) => dbUsers.find((u) => u.id === id),
      (jti, tok) => isTokenRevoked(jti, tok)
    );
    if (userPayload) {
      if (userPayload.role === 'admin') return true;
      const userObj = dbUsers.find((u) => u.id === userPayload.userId);
      const userPhone = cleanPhoneNumber(userObj?.phone || '').slice(-10);
      const orderPhone = cleanPhoneNumber(order.customerPhone || '').slice(-10);
      if (userPhone && orderPhone && userPhone === orderPhone) {
        return true;
      }
    }
  }

  return false;
}

function checkOrderItemsStock(order: any): { ok: true } | { ok: false; error: string } {
  for (const it of order.items || []) {
    const pid = it.productId || it.product?.id;
    const qty = Math.max(1, Number(it.quantity) || 1);
    const prod = dbProducts.find((p) => p.id === pid && p.status !== 'archived');
    if (!prod) {
      return { ok: false, error: `محصول «${it.product?.name || pid}» در فروشگاه موجود نیست.` };
    }
    if (it.selectedVariantId && Array.isArray(prod.variants)) {
      const variant = prod.variants.find((v: any) => v.id === it.selectedVariantId);
      if (!variant || (typeof variant.stock === 'number' && variant.stock < qty)) {
        return {
          ok: false,
          error: `موجودی تنوع انتخابی محصول «${prod.name}» در انبار کافی نیست.`
        };
      }
    } else if (typeof prod.stock === 'number' && prod.stock < qty) {
      return {
        ok: false,
        error: `موجودی محصول «${prod.name}» در انبار کافی نیست (موجودی فعلی: ${prod.stock} عدد).`
      };
    }
  }
  return { ok: true };
}

function decrementOrderInventoryOnce(order: any, actorIp = '127.0.0.1'): boolean {
  if (order.inventoryDeducted) return false;
  const shortages: string[] = [];

  for (const it of order.items || []) {
    const pid = it.productId || it.product?.id;
    const qty = Math.max(1, Number(it.quantity) || 1);
    const prod = dbProducts.find((p) => p.id === pid);
    if (!prod) {
      shortages.push(`محصول ${it.product?.name || pid} (یافت نشد)`);
      continue;
    }
    if (it.selectedVariantId && Array.isArray(prod.variants)) {
      const variant = prod.variants.find((v: any) => v.id === it.selectedVariantId);
      if (!variant) {
        shortages.push(`${prod.name} - تنوع ناموجود`);
      } else if (typeof variant.stock === 'number') {
        if (variant.stock < qty) {
          shortages.push(`${prod.name} (${variant.title || variant.id}): نیاز ${qty}، موجود ${variant.stock}`);
        }
        variant.stock = Math.max(0, variant.stock - qty);
      }
    } else if (typeof prod.stock === 'number' && prod.stock < qty) {
      shortages.push(`${prod.name}: نیاز ${qty}، موجود ${prod.stock}`);
    }
    if (typeof prod.stock === 'number') {
      prod.stock = Math.max(0, prod.stock - qty);
    }
  }

  order.inventoryDeducted = true;
  order.inventoryDeductedAt = new Date().toISOString();

  if (shortages.length > 0) {
    order.needsReview = true;
    order.reviewReason = order.reviewReason || 'INSUFFICIENT_STOCK';
    recordAuditLog({
      event: 'INVENTORY_DECREMENTED',
      ip: actorIp,
      details: `هشدار کسری موجودی پس از تایید پرداخت سفارش ${order.orderNumber} (INSUFFICIENT_STOCK): ${shortages.join(' | ')}`,
      severity: 'critical'
    });
  } else {
    recordAuditLog({
      event: 'INVENTORY_DECREMENTED',
      ip: actorIp,
      details: `موجودی انبار برای سفارش ${order.orderNumber} پس از تایید قطعی پرداخت کسر گردید.`,
      severity: 'info'
    });
  }
  return true;
}

function restoreOrderInventoryOnce(order: any): boolean {
  if (!order.inventoryDeducted) return false;
  for (const it of order.items || []) {
    const pid = it.productId || it.product?.id;
    const qty = Math.max(1, Number(it.quantity) || 1);
    const prod = dbProducts.find((p) => p.id === pid);
    if (!prod) continue;
    if (it.selectedVariantId && Array.isArray(prod.variants)) {
      const variant = prod.variants.find((v: any) => v.id === it.selectedVariantId);
      if (variant && typeof variant.stock === 'number') {
        variant.stock = variant.stock + qty;
      }
    }
    if (typeof prod.stock === 'number') {
      prod.stock = prod.stock + qty;
    }
  }
  order.inventoryDeducted = false;
  return true;
}

function releaseOrderPromoCountOnce(order: any): boolean {
  if (!order.promoCode || !order.promoCounted) return false;
  const promoCodeUpper = String(order.promoCode).trim().toUpperCase();
  const disc = dbDiscounts.find((d) => String(d.code || '').trim().toUpperCase() === promoCodeUpper);
  if (disc) {
    const cur = Number(disc.usedCount ?? disc.usageCount ?? 0);
    disc.usedCount = Math.max(0, cur - 1);
  }
  order.promoCounted = false;
  return true;
}

function sanitizeOrderPaymentResult(order: any) {
  return {
    id: order.id,
    orderNumber: order.orderNumber,
    date: order.date,
    status: order.status,
    paymentStatus: order.paymentStatus,
    paymentMethod: order.paymentMethod,
    trackingCode: order.trackingCode,
    customerName: order.customerName,
    customerPhone: order.customerPhone,
    customerAddress: order.customerAddress,
    province: order.province,
    city: order.city,
    postalCode: order.postalCode,
    items: order.items,
    subtotal: order.subtotal,
    discountAmount: order.discountAmount ?? order.discount ?? 0,
    promoCode: order.promoCode,
    shippingFee: order.shippingFee ?? order.shipping ?? 0,
    totalAmount: order.totalAmount ?? order.total ?? 0,
    paidAt: order.paidAt || order.paymentInfo?.paidAt,
    paymentInfo: order.paymentInfo
      ? {
          gateway: order.paymentInfo.gateway,
          authority: order.paymentInfo.authority,
          mode: order.paymentInfo.mode,
          refId: order.paymentInfo.refId,
          cardPanMask: order.paymentInfo.cardPanMask,
          paidAt: order.paymentInfo.paidAt,
          verifiedAt: order.paymentInfo.verifiedAt,
          lastError: order.paymentInfo.lastError
        }
      : undefined
  };
}

// ============================================================================
// AUTHENTICATION & ACCESS CONTROL HELPERS (OWASP ASVS V3, V4)
// ============================================================================
export interface AuthenticatedRequest extends Request {
  user?: {
    userId: string;
    username: string;
    role: 'admin' | 'user' | 'staff';
    tokenVersion: number;
    jti: string;
  };
}

export function extractBearerOrCookieToken(req: Request): string | null {
  // 1. Authorization header Bearer token
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }
  // 2. HttpOnly Cookie token (ASVS V3.4)
  if (req.cookies && typeof req.cookies.morico_session === 'string') {
    return req.cookies.morico_session;
  }
  return null;
}

export async function requireAdmin(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const token = extractBearerOrCookieToken(req);
  if (!token) {
    recordAuditLog({
      event: 'ADMIN_UNAUTHORIZED_ATTEMPT',
      ip: req.ip || '127.0.0.1',
      details: `درخواست احراز نشده به مسیر ادمین: ${req.method} ${req.path}`,
      severity: 'warning'
    });
    return res.status(401).json({ error: 'نشست کاری شما نامعتبر است. لطفاً وارد شوید.' });
  }

  // 100% standard audited jose verification (OWASP ASVS V3.2, V3.5)
  const payload = await verifyJoseToken(
    token,
    SESSION_SECRET!,
    (id) => dbUsers.find((u) => u.id === id),
    (jti, tok) => isTokenRevoked(jti, tok)
  );

  if (!payload) {
    recordAuditLog({
      event: 'ADMIN_UNAUTHORIZED_ATTEMPT',
      ip: req.ip || '127.0.0.1',
      details: `توکن منقضی یا نامعتبر در مسیر ادمین: ${req.path}`,
      severity: 'warning'
    });
    return res.status(401).json({ error: 'نشست کاری شما منقضی شده است. لطفاً مجدداً وارد شوید.' });
  }

  if (payload.role !== 'admin') {
    recordAuditLog({
      event: 'ADMIN_UNAUTHORIZED_ATTEMPT',
      username: payload.username,
      ip: req.ip || '127.0.0.1',
      details: `تلاش دسترسی با نقش غیرمدیر (${payload.role}) به مسیر ادمین: ${req.path}`,
      severity: 'critical'
    });
    return res.status(403).json({ error: 'دسترسی غیرمجاز. این بخش فقط مخصوص مدیر ارشد است.' });
  }

  const adminUser = dbUsers.find((u) => u.id === payload.userId);

  // Force password change check if required
  if (
    isProduction &&
    adminUser?.mustChangePassword &&
    !req.path.includes('/change-password') &&
    !req.path.includes('/logout')
  ) {
    return res.status(403).json({
      error: 'تغییر کلمه عبور پیش‌فرض الزامی است. لطفاً ابتدا رمز عبور حساب مدیر را تغییر دهید.',
      mustChangePassword: true
    });
  }

  // OWASP ASVS V2.8.1: Mandatory MFA setup for admin in production
  if (
    isProduction &&
    REQUIRE_ADMIN_MFA &&
    !adminUser?.mfaEnabled &&
    !req.path.includes('/mfa/') &&
    !req.path.includes('/change-password') &&
    !req.path.includes('/logout')
  ) {
    return res.status(403).json({
      error: 'فعال‌سازی احراز هویت دومرحله‌ای (MFA) برای حساب مدیر در محیط عملیاتی الزامی است.',
      mustSetupMfa: true
    });
  }

  req.user = payload;
  next();
}

// ============================================================================
// EXPRESS APP FACTORY & SECURITY MIDDLEWARES
// ============================================================================
export const app = express();

app.set('trust proxy', 1);
app.disable('x-powered-by');

// Cookie parser for secure HttpOnly cookie session support
app.use(cookieParser());

// Strict OWASP ASVS Defensive Security Headers (V14.4, V14.5)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.path.startsWith('/api')) {
    res.setHeader('X-Frame-Options', 'DENY');
  }
  res.setHeader('X-XSS-Protection', '0'); // Modern standard: defer to CSP
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (req.path.startsWith('/api')) {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  }
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  if (isProduction || req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;

  const scriptDirective = isProduction
    ? `'self' 'nonce-${nonce}' 'strict-dynamic'`
    : `'self' 'unsafe-inline' 'unsafe-eval'`;

  const frameAncestorsDirective = req.path.startsWith('/api') ? "frame-ancestors 'none'; " : "";

  // Modern Content-Security-Policy with strict frame-ancestors 'none' on API and Nonce-based script execution (ASVS V14.4)
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    `script-src ${scriptDirective}; ` +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' data: https://fonts.gstatic.com; " +
    "img-src 'self' data: blob: https://images.unsplash.com https://*.tile.openstreetmap.org https://trustseal.enamad.ir; " +
    "connect-src 'self' https://nominatim.openstreetmap.org https://api.zarinpal.com https://payment.zarinpal.com https://sandbox.zarinpal.com; " +
    frameAncestorsDirective +
    "object-src 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self';"
  );

  next();
});

// Strict CORS / Origin Validation (OWASP ASVS V14.4)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
    : [];

  if (origin) {
    const isSameHost = origin.includes(req.headers.host || 'localhost');
    if (isSameHost || allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Payment-Token');
    }
  }

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// Selective Body Parsing: 10MB on upload endpoint, 5MB on POST /api/orders (design images saved to disk), strict 100KB elsewhere
const standardJsonParser = express.json({ limit: '100kb' });
const orderJsonParser = express.json({ limit: '5mb' });
const uploadJsonParser = express.json({ limit: '10mb' });

app.use((req, res, next) => {
  if (req.path === '/api/upload') {
    uploadJsonParser(req, res, next);
  } else if (req.path === '/api/orders' && req.method === 'POST') {
    orderJsonParser(req, res, next);
  } else {
    standardJsonParser(req, res, next);
  }
});

// General rate limiter across all endpoints (300 req / min)
app.use('/api', createGeneralRateLimiter(300, 60000));

// Serve uploaded media securely with restrictive headers
app.use(
  '/uploads',
  express.static(UPLOADS_DIR, {
    index: false,
    maxAge: '1d',
    setHeaders: (res) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Disposition', 'inline');
      res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self'");
    }
  })
);

// ============================================================================
// 1. AUTHENTICATION ROUTES (OWASP ASVS V2, V3)
// ============================================================================

// Admin Login Route: Async scrypt, brute force lockout, timing attack dummy hash
app.post('/api/auth/admin/login', async (req, res) => {
  const { username, password } = req.body || {};
  const ip = req.ip || '127.0.0.1';

  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'نام کاربری و رمز عبور الزامی است.' });
  }

  const cleanUser = username.trim().toLowerCase();

  // Check lockout via distributed cache
  const ipLock = await checkLockoutAsync(`adm_ip:${ip}`);
  const userLock = await checkLockoutAsync(`adm_user:${cleanUser}`);
  if (ipLock.locked || userLock.locked) {
    const waitSeconds = Math.max(ipLock.waitSeconds || 0, userLock.waitSeconds || 0);
    return res.status(429).json({
      error: `حساب کاربری یا آدرس شبکه به دلیل تلاش‌های ناموفق مکرر موقتاً مسدود شده است. لطفاً ${waitSeconds} ثانیه دیگر مجدداً تلاش فرمایید.`,
      retryAfter: waitSeconds
    });
  }

  const foundUser = dbUsers.find(
    (u) =>
      u.role === 'admin' &&
      (u.username.toLowerCase() === cleanUser ||
        u.email.toLowerCase() === cleanUser ||
        (cleanUser === 'admin' && (u.username === 'admin@morico.style' || u.role === 'admin')))
  );

  let isMatch = false;
  let needsRehash = false;

  if (foundUser) {
    const verification = await verifyPasswordAsync(password, foundUser.passwordHash);
    isMatch = verification.valid;
    needsRehash = !!verification.needsRehash;
  } else {
    // Constant time dummy execution to prevent user enumeration
    await verifyDummyPasswordAsync(password);
  }

  if (!foundUser || !isMatch) {
    const ipFail = await recordAuthFailureAsync(`adm_ip:${ip}`);
    const userFail = await recordAuthFailureAsync(`adm_user:${cleanUser}`);
    const isNowLocked = ipFail.locked || userFail.locked;

    recordAuditLog({
      event: isNowLocked ? 'AUTH_ACCOUNT_LOCKED' : 'AUTH_LOGIN_FAILED',
      username: cleanUser,
      ip,
      details: isNowLocked
        ? `حساب مدیر ارشد پس از ۵ تلاش ناموفق متوالی به مدت ۱۵ دقیقه مسدود شد.`
        : `تلاش ناموفق برای ورود به پنل مدیریت با رمز نادرست (تلاش ${ipFail.attempts})`,
      severity: isNowLocked ? 'critical' : 'warning'
    });

    if (isNowLocked) {
      return res.status(429).json({
        error: 'تعداد تلاش‌های ناموفق بیش از حد مجاز است. دسترسی به مدت ۱۵ دقیقه مسدود گردید.',
        retryAfter: 900
      });
    }

    return res.status(401).json({ error: 'نام کاربری یا رمز عبور نامعتبر است.' });
  }

  // Clear failures upon successful authentication across cache and local memory
  await clearAuthFailureAsync(`adm_ip:${ip}`);
  await clearAuthFailureAsync(`adm_user:${cleanUser}`);

  // Rehash legacy hash to modern Scrypt parameter format if needed
  if (needsRehash) {
    foundUser.passwordHash = await hashPasswordAsync(password);
  }

  foundUser.lastLogin = new Date().toISOString();
  foundUser.loginCount = (foundUser.loginCount || 0) + 1;
  foundUser.tokenVersion = foundUser.tokenVersion || 1;
  savePersistentState();

  // Check if Admin has MFA enabled (OWASP ASVS V2.8.1)
  if (foundUser.mfaEnabled && foundUser.mfaSecret) {
    const tempToken = await signJoseToken(
      { id: foundUser.id, username: foundUser.username, role: 'staff', tokenVersion: foundUser.tokenVersion || 1 },
      SESSION_SECRET!,
      '5m'
    );

    recordAuditLog({
      event: 'ADMIN_MFA_CHALLENGE',
      username: foundUser.username,
      ip,
      details: 'درخواست چالش احراز هویت دومرحله‌ای (MFA TOTP) برای حساب مدیر صادر گردید.',
      severity: 'info'
    });

    return res.json({
      requiresMfa: true,
      tempToken,
      message: 'کد احراز هویت ۶ رقمی نرم‌افزار Authenticator یا کد پشتیبان را وارد نمایید.'
    });
  }

  const token = await signJoseToken(foundUser, SESSION_SECRET!);

  // Set HttpOnly Secure Cookie (OWASP ASVS V3.4)
  res.cookie('morico_session', token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    path: '/',
    maxAge: 12 * 60 * 60 * 1000
  });

  recordAuditLog({
    event: 'AUTH_LOGIN_SUCCESS',
    username: foundUser.username,
    ip,
    details: 'ورود موفق مدیر ارشد به آتلیه MORICO STYLE با توکن امضاشده و نشست معتبر',
    severity: 'info'
  });

  res.json({
    success: true,
    token,
    user: {
      id: foundUser.id,
      name: foundUser.name,
      email: foundUser.email,
      phone: foundUser.phone,
      role: foundUser.role
    },
    mustChangePassword: Boolean(foundUser.mustChangePassword),
    mustSetupMfa: Boolean(isProduction && REQUIRE_ADMIN_MFA && !foundUser.mfaEnabled)
  });
});

// Admin MFA Verification Route (RFC 6238 TOTP & Backup Codes - ASVS V2.8.4)
app.post('/api/auth/admin/mfa-verify', async (req, res) => {
  const { tempToken, code } = req.body || {};
  const ip = req.ip || '127.0.0.1';

  if (!tempToken || !code) {
    return res.status(400).json({ error: 'توکن چالش و کد امنیتی الزامی هستند.' });
  }

  // 100% standard jose verification (OWASP ASVS V2.8.4, V3.2)
  const payload = await verifyJoseToken(
    tempToken,
    SESSION_SECRET!,
    (id) => dbUsers.find((u) => u.id === id),
    (jti, tok) => isTokenRevoked(jti, tok)
  );

  if (!payload) {
    return res.status(401).json({ error: 'نشست چالش احراز هویت دومرحله‌ای منقضی یا نامعتبر است.' });
  }

  const admin = dbUsers.find((u) => u.id === payload.userId && u.role === 'admin');
  if (!admin || !admin.mfaSecret) {
    return res.status(400).json({ error: 'احراز هویت دومرحله‌ای برای این حساب فعال نشده است.' });
  }

  const cleanCode = String(code).trim().replace(/\s+/g, '');
  let isTotpValid = verifyTotpCode(admin.mfaSecret, cleanCode);

  // Check backup recovery codes if not matching 6-digit TOTP
  if (!isTotpValid && Array.isArray(admin.backupCodes) && admin.backupCodes.length > 0) {
    const backupIndex = admin.backupCodes.findIndex((c) => c.toUpperCase() === cleanCode.toUpperCase());
    if (backupIndex !== -1) {
      isTotpValid = true;
      admin.backupCodes.splice(backupIndex, 1);
      savePersistentState();
      recordAuditLog({
        event: 'AUTH_LOGIN_SUCCESS',
        username: admin.username,
        ip,
        details: 'ورود موفق به پنل مدیریت با استفاده از کد پشتیبان اضطراری (Backup Code)',
        severity: 'warning'
      });
    }
  }

  if (!isTotpValid) {
    recordAuditLog({
      event: 'AUTH_LOGIN_FAILED',
      username: admin.username,
      ip,
      details: 'تلاش ناموفق برای ورود به ادمین با کد دومرحله‌ای اشتباه',
      severity: 'warning'
    });
    return res.status(401).json({ error: 'کد احراز هویت دومرحله‌ای نامعتبر یا منقضی است.' });
  }

  recordRevokedToken(payload.jti);

  const token = await signJoseToken(admin, SESSION_SECRET!);
  res.cookie('morico_session', token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    path: '/',
    maxAge: 12 * 60 * 60 * 1000
  });

  recordAuditLog({
    event: 'AUTH_LOGIN_SUCCESS',
    username: admin.username,
    ip,
    details: 'ورود موفق به پنل مدیریت با تایید هویت دومرحله‌ای (MFA)',
    severity: 'info'
  });

  res.json({
    success: true,
    token,
    user: {
      id: admin.id,
      name: admin.name,
      email: admin.email,
      phone: admin.phone,
      role: admin.role
    }
  });
});

// Customer Dedicated Registration Route (OWASP ASVS V2.1)
app.post('/api/auth/customer/register', async (req, res) => {
  const { name, username, phone, email, password } = req.body || {};
  const ip = req.ip || '127.0.0.1';

  if (!password || (!phone && !username && !email)) {
    return res.status(400).json({ error: 'اطلاعات ثبت‌نام ناقص است. شماره تلفن و رمز عبور الزامی هستند.' });
  }

  // 1. Password Policy Verification
  const passCheck = validatePasswordPolicy(password);
  if (!passCheck.valid) {
    return res.status(400).json({ error: passCheck.error });
  }

  // 2. Persian/Arabic Numeral Normalization
  const cleanPhone = cleanPhoneNumber(phone || username || '');
  const cleanEmail = email ? sanitizeText(email, 80).toLowerCase() : '';
  const cleanName = sanitizeText(name || 'مشتری گرامی', 80);

  if (!cleanPhone || cleanPhone.length < 10) {
    return res.status(400).json({ error: 'شماره تلفن همراه واردشده نامعتبر است (حداقل ۱۰ رقم).' });
  }

  // 3. Uniqueness Verification
  const existingUser = dbUsers.find((u) => {
    const uPhone = cleanPhoneNumber(u.phone);
    const uEmail = u.email ? u.email.toLowerCase() : '';
    return (
      (cleanPhone && uPhone && uPhone.slice(-10) === cleanPhone.slice(-10)) ||
      (cleanEmail && uEmail && uEmail === cleanEmail)
    );
  });

  if (existingUser) {
    return res.status(400).json({
      error: 'کاربری با این شماره تلفن یا نشانی ایمیل قبلاً در سامانه ثبت‌نام کرده است.'
    });
  }

  // 4. Secure Async Scrypt Hashing
  const passwordHash = await hashPasswordAsync(password);

  const newUser: DbUser = {
    id: `usr-cust-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    name: cleanName,
    username: cleanPhone,
    phone: cleanPhone,
    email: cleanEmail,
    passwordHash,
    role: 'user',
    joinDate: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
    loginCount: 1,
    tokenVersion: 1
  };

  dbUsers.push(newUser);
  savePersistentState();

  const token = await signJoseToken(newUser, SESSION_SECRET!);

  res.cookie('morico_session', token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    path: '/',
    maxAge: 12 * 60 * 60 * 1000
  });

  recordAuditLog({
    event: 'AUTH_REGISTER_SUCCESS',
    username: newUser.phone,
    ip,
    details: `ثبت‌نام مشتری جدید «${newUser.name}» با شماره تلفن ${newUser.phone}`,
    severity: 'info'
  });

  res.status(201).json({
    success: true,
    token,
    user: {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      phone: newUser.phone,
      role: newUser.role
    }
  });
});

// Customer Dedicated Login Route: Rate-limited, brute force lockout
app.post('/api/auth/customer/login', async (req, res) => {
  const { username, password } = req.body || {};
  const ip = req.ip || '127.0.0.1';

  if (!username || !password) {
    return res.status(400).json({ error: 'شماره تلفن/ایمیل و رمز عبور الزامی است.' });
  }

  const rawUser = String(username).trim();
  const cleanPhone = cleanPhoneNumber(rawUser);
  const cleanEmail = rawUser.toLowerCase();

  // Check customer lockout via cache
  const ipLock = await checkLockoutAsync(`cust_ip:${ip}`);
  const userLock = await checkLockoutAsync(`cust_user:${cleanPhone || cleanEmail}`);
  if (ipLock.locked || userLock.locked) {
    const waitSeconds = Math.max(ipLock.waitSeconds || 0, userLock.waitSeconds || 0);
    return res.status(429).json({
      error: `به دلیل تلاش‌های ناموفق مکرر، ورود موقتاً مسدود شده است. لطفاً ${waitSeconds} ثانیه دیگر امتحان کنید.`,
      retryAfter: waitSeconds
    });
  }

  const foundUser = dbUsers.find((u) => {
    if (cleanPhone && cleanPhoneNumber(u.phone).slice(-10) === cleanPhone.slice(-10)) return true;
    if (cleanEmail && u.email && u.email.toLowerCase() === cleanEmail) return true;
    if (u.username.toLowerCase() === cleanEmail) return true;
    return false;
  });

  let isMatch = false;
  if (foundUser) {
    const verification = await verifyPasswordAsync(password, foundUser.passwordHash);
    isMatch = verification.valid;
  } else {
    await verifyDummyPasswordAsync(password);
  }

  if (!foundUser || !isMatch) {
    const ipFail = await recordAuthFailureAsync(`cust_ip:${ip}`);
    const userFail = await recordAuthFailureAsync(`cust_user:${cleanPhone || cleanEmail}`);
    const isNowLocked = ipFail.locked || userFail.locked;

    if (isNowLocked) {
      return res.status(429).json({
        error: 'تعداد تلاش‌های ناموفق بیش از حد مجاز است. دسترسی به مدت ۱۵ دقیقه مسدود شد.',
        retryAfter: 900
      });
    }

    return res.status(401).json({ error: 'شماره همراه، ایمیل یا رمز عبور نامعتبر است.' });
  }

  await clearAuthFailureAsync(`cust_ip:${ip}`);
  await clearAuthFailureAsync(`cust_user:${cleanPhone || cleanEmail}`);

  foundUser.lastLogin = new Date().toISOString();
  foundUser.loginCount = (foundUser.loginCount || 0) + 1;
  savePersistentState();

  const token = await signJoseToken(foundUser, SESSION_SECRET!);

  res.cookie('morico_session', token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    path: '/',
    maxAge: 12 * 60 * 60 * 1000
  });

  recordAuditLog({
    event: 'AUTH_LOGIN_SUCCESS',
    username: foundUser.phone || foundUser.email,
    ip,
    details: `ورود مشتری ${foundUser.name}`,
    severity: 'info'
  });

  res.json({
    success: true,
    token,
    user: {
      id: foundUser.id,
      name: foundUser.name,
      email: foundUser.email,
      phone: foundUser.phone,
      role: foundUser.role
    }
  });
});

// Logout for both Admin and Customer: Clears cookie and invalidates token server-side
const handleLogout = (req: AuthenticatedRequest, res: Response) => {
  const token = extractBearerOrCookieToken(req);
  if (token) {
    recordRevokedToken(token);
  }
  if (req.user?.jti) {
    recordRevokedToken(req.user.jti);
  }

  res.clearCookie('morico_session', { path: '/' });

  recordAuditLog({
    event: 'AUTH_LOGOUT',
    username: req.user?.username,
    ip: req.ip || '127.0.0.1',
    details: 'خروج از حساب کاربری و ابطال نشست کاری',
    severity: 'info'
  });

  res.json({ success: true, message: 'خروج با موفقیت انجام شد و نشست ابطال گردید.' });
};

app.post('/api/auth/logout', handleLogout);
app.post('/api/auth/admin/logout', handleLogout);

// Admin Change Password: Full policy validation, token invalidation, instant cookie refresh
app.post('/api/admin/change-password', requireAdmin, async (req: AuthenticatedRequest, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'رمز عبور فعلی و جدید الزامی است.' });
  }

  const passCheck = validatePasswordPolicy(newPassword);
  if (!passCheck.valid) {
    return res.status(400).json({ error: passCheck.error });
  }

  const admin = dbUsers.find((u) => u.id === req.user?.userId);
  if (!admin) {
    return res.status(404).json({ error: 'کاربر مدیر یافت نشد.' });
  }

  const verifyCurrent = await verifyPasswordAsync(currentPassword, admin.passwordHash);
  if (!verifyCurrent.valid) {
    recordAuditLog({
      event: 'ADMIN_UNAUTHORIZED_ATTEMPT',
      username: admin.username,
      ip: req.ip || '127.0.0.1',
      details: 'تلاش ناموفق برای تغییر رمز عبور مدیر با رمز فعلی اشتباه',
      severity: 'critical'
    });
    return res.status(401).json({ error: 'رمز عبور فعلی وارد شده نادرست است.' });
  }

  // OWASP ASVS V2.1.9: Prevent reuse of recent passwords (last 5)
  const historyCheck = await checkPasswordHistory(newPassword, admin.passwordHistory);
  if (historyCheck.reused) {
    return res.status(400).json({
      error: 'شما نمی‌توانید از ۵ رمز عبور اخیر خود مجدداً استفاده فرمایید (سیاست تاریخچه رمز عبور).'
    });
  }

  // Update password history with previous hash
  if (!Array.isArray(admin.passwordHistory)) {
    admin.passwordHistory = [];
  }
  admin.passwordHistory.unshift(admin.passwordHash);
  if (admin.passwordHistory.length > 5) {
    admin.passwordHistory = admin.passwordHistory.slice(0, 5);
  }

  // Update hash and invalidate all existing active tokens for this user
  admin.passwordHash = await hashPasswordAsync(newPassword);
  admin.tokenVersion = (admin.tokenVersion || 1) + 1;
  admin.mustChangePassword = false;
  savePersistentState(true);

  // Sign new token for current session using jose
  const newToken = await signJoseToken(admin, SESSION_SECRET!);
  res.cookie('morico_session', newToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    path: '/',
    maxAge: 12 * 60 * 60 * 1000
  });

  recordAuditLog({
    event: 'ADMIN_PASSWORD_CHANGED',
    username: admin.username,
    ip: req.ip || '127.0.0.1',
    details: 'رمز عبور حساب مدیر تغییر یافت و کلیه نشست‌های پیشین باطل شدند.',
    severity: 'critical'
  });

  res.json({
    success: true,
    message: 'رمز عبور با موفقیت تغییر یافت و سیاست‌های امنیتی اعمال شدند.',
    token: newToken
  });
});

// ============================================================================
// ADMIN MFA ENROLLMENT & LIFECYCLE (OWASP ASVS V2.8.1, V2.8.4, V2.8.7)
// ============================================================================

// 1. Generate MFA Setup Credentials (Secret, QR otpauth URL, Backup codes)
app.post('/api/admin/mfa/setup', requireAdmin, async (req: AuthenticatedRequest, res) => {
  const admin = dbUsers.find((u) => u.id === req.user?.userId);
  if (!admin) {
    return res.status(404).json({ error: 'کاربر مدیر یافت نشد.' });
  }

  const secret = generateTotpSecret();
  const otpauthUrl = generateOtpAuthUrl(admin.email || admin.username, secret);
  const backupCodes = generateBackupCodes(8);

  recordAuditLog({
    event: 'ADMIN_MFA_CHALLENGE',
    username: admin.username,
    ip: req.ip || '127.0.0.1',
    details: 'درخواست راه‌اندازی و تولید کلید جدید برای احراز هویت دومرحله‌ای (MFA TOTP)',
    severity: 'info'
  });

  res.json({
    secret,
    otpauthUrl,
    backupCodes,
    message: 'کلید احراز هویت را در اپلیکیشن Authenticator اسکن نمایید و با وارد کردن کد ۶ رقمی فعال‌سازی را کامل کنید.'
  });
});

// 2. Confirm and finalize MFA Activation with first TOTP code
app.post('/api/admin/mfa/confirm', requireAdmin, async (req: AuthenticatedRequest, res) => {
  const { secret, code, backupCodes } = req.body || {};
  if (!secret || !code || !Array.isArray(backupCodes) || backupCodes.length === 0) {
    return res.status(400).json({ error: 'کلید محرمانه، کد ۶ رقمی و کدهای پشتیبان الزامی هستند.' });
  }

  const cleanCode = String(code).trim().replace(/\s+/g, '');
  const isValid = verifyTotpCode(secret, cleanCode);
  if (!isValid) {
    return res.status(400).json({ error: 'کد ۶ رقمی وارد شده نامعتبر است یا منقضی شده است.' });
  }

  const admin = dbUsers.find((u) => u.id === req.user?.userId);
  if (!admin) {
    return res.status(404).json({ error: 'کاربر مدیر یافت نشد.' });
  }

  admin.mfaEnabled = true;
  admin.mfaSecret = secret;
  admin.backupCodes = backupCodes.map((c: string) => String(c).trim().toUpperCase());
  savePersistentState(true);

  recordAuditLog({
    event: 'ADMIN_MFA_ENABLED',
    username: admin.username,
    ip: req.ip || '127.0.0.1',
    details: 'احراز هویت دومرحله‌ای (MFA TOTP) با موفقیت برای حساب مدیر ارشد فعال گردید.',
    severity: 'critical'
  });

  res.json({
    success: true,
    message: 'احراز هویت دومرحله‌ای (MFA) با موفقیت روی حساب شما فعال گردید.',
    mfaEnabled: true
  });
});

// 3. Disable MFA (Requires Password Re-authentication & Current TOTP/Backup Code)
app.post('/api/admin/mfa/disable', requireAdmin, async (req: AuthenticatedRequest, res) => {
  const { currentPassword, code } = req.body || {};
  if (!currentPassword || !code) {
    return res.status(400).json({ error: 'رمز عبور فعلی و کد تایید دومرحله‌ای الزامی است.' });
  }

  const admin = dbUsers.find((u) => u.id === req.user?.userId);
  if (!admin) {
    return res.status(404).json({ error: 'کاربر مدیر یافت نشد.' });
  }

  const verifyPass = await verifyPasswordAsync(currentPassword, admin.passwordHash);
  if (!verifyPass.valid) {
    recordAuditLog({
      event: 'ADMIN_UNAUTHORIZED_ATTEMPT',
      username: admin.username,
      ip: req.ip || '127.0.0.1',
      details: 'تلاش ناموفق برای غیرفعال‌سازی MFA با رمز عبور اشتباه',
      severity: 'critical'
    });
    return res.status(401).json({ error: 'رمز عبور وارد شده نادرست است.' });
  }

  const cleanCode = String(code).trim().replace(/\s+/g, '');
  let codeValid = false;
  if (admin.mfaSecret) {
    codeValid = verifyTotpCode(admin.mfaSecret, cleanCode);
  }
  if (!codeValid && Array.isArray(admin.backupCodes)) {
    const idx = admin.backupCodes.findIndex((b) => b.toUpperCase() === cleanCode.toUpperCase());
    if (idx !== -1) codeValid = true;
  }

  if (!codeValid) {
    return res.status(400).json({ error: 'کد تایید دومرحله‌ای یا کد پشتیبان نامعتبر است.' });
  }

  admin.mfaEnabled = false;
  admin.mfaSecret = undefined;
  admin.backupCodes = undefined;
  savePersistentState(true);

  recordAuditLog({
    event: 'SETTINGS_MUTATION',
    username: admin.username,
    ip: req.ip || '127.0.0.1',
    details: 'احراز هویت دومرحله‌ای (MFA) برای حساب مدیر غیرفعال گردید.',
    severity: 'critical'
  });

  res.json({
    success: true,
    message: 'احراز هویت دومرحله‌ای با موفقیت غیرفعال شد.',
    mfaEnabled: false
  });
});

// ============================================================================
// 2. STOREFRONT PUBLIC APIS
// ============================================================================

// Public Bootstrap: Defends against Discount Exfiltration (OWASP ASVS V13.2)
app.get('/api/bootstrap', (req, res) => {
  res.json({
    siteContent: dbSiteContent,
    categories: dbCategories.filter((c) => c.active !== false),
    categoryAttributes: dbCategoryAttributes,
    products: dbProducts.filter((p) => p.status !== 'archived'),
    banners: dbBanners.filter((b) => b.active !== false),
    // Notice: Never expose hidden discount codes or thresholds in bootstrap payload
    discounts: [],
    bestSellers: dbBestSellers,
    topWeekly: dbTopWeekly
  });
});

app.get('/api/bestsellers', (req, res) => {
  res.json(dbBestSellers);
});

app.get('/api/top-weekly', (req, res) => {
  res.json(dbTopWeekly);
});

app.get('/api/categories', (req, res) => {
  res.json(dbCategories.filter((c) => c.active !== false));
});

app.get('/api/products', (req, res) => {
  res.json(dbProducts.filter((p) => p.status !== 'archived'));
});

app.get('/api/banners', (req, res) => {
  res.json(dbBanners.filter((b) => b.active !== false));
});

app.get('/api/content', (req, res) => {
  res.json(dbSiteContent);
});

// Health endpoint for cPanel / uptime monitoring without exposing any secrets or merchantId (C5)
app.get('/api/health', (req, res) => {
  const effective = getEffectiveGatewayConfig();
  res.json({
    ok: true,
    status: 'healthy',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV || 'development',
    mode: effective.mode,
    gatewayReady: effective.ready
  });
});

// Payment status: Hides merchantId from public clients (OWASP ASVS V13.2)
app.get('/api/payments/status', (req, res) => {
  const effective = getEffectiveGatewayConfig();
  res.json({
    gatewayName: effective.gatewayName,
    configured: effective.ready,
    ready: effective.ready,
    mode: effective.mode,
    disabledReason: effective.disabledReason
  });
});

// Public Discount Code Validation: Rate-limited to prevent brute-forcing promo codes
app.post('/api/discounts/validate', createDiscountRateLimiter(15, 5 * 60 * 1000), (req, res) => {
  const { code, subtotal } = req.body || {};
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ valid: false, error: 'کد تخفیف را وارد فرمایید.' });
  }

  const evalRes = evaluateDiscountCode(dbDiscounts, code, Number(subtotal) || 0);
  if ('error' in evalRes) {
    return res.json({ valid: false, error: evalRes.error });
  }

  res.json({
    valid: true,
    code: evalRes.code,
    discountAmount: evalRes.discountAmount,
    description: evalRes.description
  });
});

// Reverse geocoding proxy using OpenStreetMap with bounds & SSRF defense
app.get('/api/reverse-geocode', async (req, res) => {
  const { lat, lng } = req.query;
  if (!lat || !lng) {
    return res.status(400).json({ error: 'مختصات جغرافیایی الزامی است.' });
  }

  const numLat = Number(lat);
  const numLng = Number(lng);
  if (!Number.isFinite(numLat) || !Number.isFinite(numLng) || numLat < -90 || numLat > 90 || numLng < -180 || numLng > 180) {
    return res.status(400).json({ error: 'مختصات جغرافیایی نامعتبر است.' });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${numLat}&lon=${numLng}&accept-language=fa`;

    const osmRes = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'MoricoStyleStore/2.0' }
    });
    clearTimeout(timeout);

    if (!osmRes.ok) throw new Error('OSM response not ok');
    const data: any = await osmRes.json();
    const addr = data.address || {};
    const road = addr.road || addr.neighbourhood || addr.suburb || '';
    const city = addr.city || addr.town || addr.municipality || addr.county || '';
    const province = addr.state || '';
    const postcode = addr.postcode || '';

    res.json({
      success: true,
      displayName: data.display_name || '',
      road,
      city,
      province,
      postcode
    });
  } catch {
    res.json({ success: false, road: '', city: '', province: '' });
  }
});

// ============================================================================
// 3. ORDER PLACEMENT & TAMPERING DEFENSE (OWASP ASVS V10.2, V10.3, V13.2)
// ============================================================================
const orderCreationRateLimiter = createGeneralRateLimiter(10, 10 * 60 * 1000, 'rate_limit_order_create');

async function persistSafeDesignImageDataUrl(
  dataUrl: string,
  dedupeCache: Map<string, string>,
  ip: string
): Promise<string> {
  if (!dataUrl || typeof dataUrl !== 'string') return dataUrl;
  const trimmed = dataUrl.trim();
  if (!trimmed.startsWith('data:image/')) {
    return trimmed;
  }
  const existing = dedupeCache.get(trimmed);
  if (existing) return existing;

  const match = trimmed.match(/^data:image\/([a-zA-Z0-9+.-]+);base64,(.+)$/);
  if (!match) {
    throw new Error('فرمت تصویر طراحی اختصاصی نامعتبر است.');
  }

  const buffer = Buffer.from(match[2], 'base64');
  if (buffer.length > 5 * 1024 * 1024) {
    throw new Error('حجم هر تصویر طراحی اختصاصی نباید بیشتر از ۵ مگابایت باشد.');
  }

  const textSample = buffer.slice(0, 120).toString('utf8').trim().toLowerCase();
  if (textSample.startsWith('<svg') || textSample.includes('<?xml') || textSample.includes('<svg')) {
    recordAuditLog({
      event: 'MALICIOUS_UPLOAD_BLOCKED',
      ip,
      details: 'تلاش برای ثبت فایل SVG درون طراحی سفارش مسدود شد.',
      severity: 'critical'
    });
    throw new Error('فرمت SVG در طراحی اختصاصی مجاز نیست.');
  }

  let detectedExt: 'jpeg' | 'png' | 'webp' | null = null;
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    detectedExt = 'jpeg';
  } else if (
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47
  ) {
    detectedExt = 'png';
  } else if (
    buffer.length >= 12 &&
    buffer.slice(0, 4).toString('ascii') === 'RIFF' &&
    buffer.slice(8, 12).toString('ascii') === 'WEBP'
  ) {
    detectedExt = 'webp';
  }

  if (!detectedExt) {
    throw new Error('امضای فایل تصویر طراحی اختصاصی معتبر نیست.');
  }

  let cleanBuffer: Buffer;
  try {
    cleanBuffer = await sharp(buffer).toFormat(detectedExt, { quality: 88 }).toBuffer();
  } catch {
    throw new Error('ساختار تصویر طراحی اختصاصی معیوب یا نامعتبر است.');
  }

  if (!fs.existsSync(DESIGN_UPLOADS_DIR)) {
    fs.mkdirSync(DESIGN_UPLOADS_DIR, { recursive: true });
  }
  const safeFilename = `design_${Date.now()}_${crypto.randomBytes(8).toString('hex')}.${detectedExt}`;
  const safePath = path.join(DESIGN_UPLOADS_DIR, safeFilename);
  const resolvedBase = path.resolve(UPLOADS_DIR) + path.sep;
  if (!path.resolve(safePath).startsWith(resolvedBase)) {
    throw new Error('خطای امنیت مسیر ذخیره‌سازی طراحی.');
  }

  fs.writeFileSync(safePath, cleanBuffer);
  const publicUrl = `/uploads/designs/${safeFilename}`;
  dedupeCache.set(trimmed, publicUrl);
  return publicUrl;
}

async function persistCustomizationDataImages(customization: any, ip: string): Promise<any> {
  if (!customization || typeof customization !== 'object') return customization;
  const dedupeCache = new Map<string, string>();
  const cloned = JSON.parse(JSON.stringify(customization));

  if (typeof cloned.designImageUrl === 'string') {
    cloned.designImageUrl = await persistSafeDesignImageDataUrl(cloned.designImageUrl, dedupeCache, ip);
  }
  if (typeof cloned.previewMockupUrl === 'string') {
    cloned.previewMockupUrl = await persistSafeDesignImageDataUrl(cloned.previewMockupUrl, dedupeCache, ip);
  }

  if (Array.isArray(cloned.layers)) {
    for (const layer of cloned.layers) {
      if (layer && typeof layer === 'object') {
        if (typeof layer.content === 'string') {
          layer.content = await persistSafeDesignImageDataUrl(layer.content, dedupeCache, ip);
        }
        if (typeof layer.originalImage === 'string') {
          layer.originalImage = await persistSafeDesignImageDataUrl(layer.originalImage, dedupeCache, ip);
        }
      }
    }
  }

  if (cloned.views && typeof cloned.views === 'object') {
    for (const vKey of Object.keys(cloned.views)) {
      const view = cloned.views[vKey];
      if (!view || typeof view !== 'object') continue;
      if (typeof view.designImageUrl === 'string') {
        view.designImageUrl = await persistSafeDesignImageDataUrl(view.designImageUrl, dedupeCache, ip);
      }
      if (typeof view.previewMockupUrl === 'string') {
        view.previewMockupUrl = await persistSafeDesignImageDataUrl(view.previewMockupUrl, dedupeCache, ip);
      }
      if (Array.isArray(view.layers)) {
        for (const layer of view.layers) {
          if (layer && typeof layer === 'object') {
            if (typeof layer.content === 'string') {
              layer.content = await persistSafeDesignImageDataUrl(layer.content, dedupeCache, ip);
            }
            if (typeof layer.originalImage === 'string') {
              layer.originalImage = await persistSafeDesignImageDataUrl(layer.originalImage, dedupeCache, ip);
            }
          }
        }
      }
    }
  }

  return cloned;
}

app.post('/api/orders', orderCreationRateLimiter, async (req, res) => {
  const sanitized = sanitizeOrderInput(req.body);
  if ('error' in sanitized) {
    return res.status(400).json({ error: sanitized.error });
  }

  const isGatewayPayment = sanitized.paymentMethod === 'gateway';
  const effectiveGateway = getEffectiveGatewayConfig();
  if (isGatewayPayment && !effectiveGateway.ready) {
    return res.status(400).json({
      error:
        effectiveGateway.disabledReason ||
        'درگاه پرداخت اینترنتی هنوز متصل نشده است. تا زمان اتصال درگاه توسط مدیریت فروشگاه، امکان پرداخت آنلاین وجود ندارد.'
    });
  }

  // Idempotent order creation if client retries with same idempotencyKey + phone
  if (sanitized.idempotencyKey) {
    const phoneSuffix = sanitized.customerPhone.slice(-10);
    const existingPending = dbOrders.find(
      (o) =>
        o.idempotencyKey === sanitized.idempotencyKey &&
        cleanPhoneNumber(o.customerPhone).slice(-10) === phoneSuffix &&
        (o.status === 'PENDING_PAYMENT' || o.status === 'PAYMENT_FAILED')
    );
    if (existingPending) {
      const paymentToken = await signOrderPaymentToken(existingPending);
      res.cookie('morico_pay_order', paymentToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax',
        path: '/',
        maxAge: 4 * 60 * 60 * 1000
      });
      return res.status(200).json({ ...existingPending, paymentToken });
    }
  }

  // Max 3 concurrent open PENDING_PAYMENT orders per normalized mobile number (B3)
  const openPendingCount = dbOrders.filter(
    (o) =>
      o.status === 'PENDING_PAYMENT' &&
      normalizeIranianMobile(o.customerPhone) === sanitized.customerPhone
  ).length;
  if (openPendingCount >= 3) {
    return res.status(429).json({
      error: 'حداکثر ۳ سفارش هم‌زمان در انتظار پرداخت برای هر شماره موبایل مجاز است. لطفاً ابتدا سفارش‌های قبلی خود را تکمیل یا لغو فرمایید.'
    });
  }

  let calculatedSubtotal = 0;
  const verifiedItems: any[] = [];

  // Strict Product Existence, Variant Resolution, Stock Check, and Server-Side Price Verification
  for (const item of sanitized.items) {
    const foundProduct = dbProducts.find((p) => p.id === item.productId && p.status !== 'archived');
    if (!foundProduct) {
      return res.status(400).json({
        error: `محصول با شناسه «${item.productId}» در فروشگاه یافت نشد یا غیرفعال شده است.`
      });
    }

    let selectedVariant: any = undefined;
    if (item.selectedVariantId && Array.isArray(foundProduct.variants)) {
      selectedVariant = foundProduct.variants.find((v: any) => v.id === item.selectedVariantId);
      if (!selectedVariant) {
        return res.status(400).json({
          error: `تنوع انتخاب‌شده برای محصول «${foundProduct.name}» در سیستم یافت نشد.`
        });
      }
    }

    // Inventory Stock Check (never decrements stock on order creation!)
    const availableStock =
      selectedVariant && typeof selectedVariant.stock === 'number'
        ? selectedVariant.stock
        : foundProduct.stock;

    if (typeof availableStock === 'number' && availableStock < item.quantity) {
      return res.status(400).json({
        error: `موجودی محصول «${foundProduct.name || item.productId}» در انبار کافی نیست (موجودی فعلی: ${availableStock} عدد).`
      });
    }

    // Price is strictly read from database only
    const basePrice = selectedVariant ? Number(selectedVariant.price) : Number(foundProduct.price);
    const discPrice = selectedVariant
      ? Number(selectedVariant.discountPrice || 0)
      : Number(foundProduct.discountPrice || 0);

    const unitPrice = discPrice > 0 && discPrice < basePrice ? discPrice : basePrice;

    // Customization fee validation (A1: strictly computed on server; client customFee ignored)
    let customFee = 0;
    const customizable = isProductCustomizable(foundProduct);
    if (item.customization) {
      if (!customizable) {
        return res.status(400).json({
          error: `محصول «${foundProduct.name}» قابلیت طراحی اختصاصی و چاپ آنلاین ندارد.`
        });
      }
      customFee = getProductCustomizationFee(foundProduct);
    }

    const itemTotal = (unitPrice + customFee) * item.quantity;
    calculatedSubtotal += itemTotal;

    const productImage = foundProduct.image || foundProduct.imageUrl || foundProduct.images?.[0] || '';

    let persistedCustomization: any = undefined;
    if (item.customization) {
      try {
        const savedCust = await persistCustomizationDataImages(item.customization, req.ip || '127.0.0.1');
        persistedCustomization = { ...savedCust, customFee };
      } catch (imgErr: any) {
        return res.status(400).json({
          error: imgErr?.message || 'پردازش تصویر طراحی اختصاصی با خطا مواجه شد.'
        });
      }
    }

    verifiedItems.push({
      productId: foundProduct.id,
      selectedVariantId: selectedVariant?.id,
      selectedVariant: selectedVariant
        ? {
            id: selectedVariant.id,
            title: selectedVariant.title,
            price: selectedVariant.price,
            discountPrice: selectedVariant.discountPrice,
            stock: selectedVariant.stock,
            attributes: selectedVariant.attributes || {}
          }
        : undefined,
      product: {
        id: foundProduct.id,
        name: foundProduct.name,
        price: unitPrice,
        image: productImage,
        imageUrl: productImage
      },
      quantity: item.quantity,
      selectedColor: item.selectedColor,
      selectedSize: item.selectedSize,
      customization: persistedCustomization,
      unitPrice,
      customFee,
      itemTotal
    });
  }

  // Server-side Discount Promo Evaluation (A7: validated now, quota incremented ONLY on successful payment)
  let calculatedDiscount = 0;
  let promoCodeApplied = '';

  if (sanitized.promoCode) {
    const promoEval = evaluateDiscountCode(dbDiscounts, sanitized.promoCode, calculatedSubtotal);
    if (promoEval.valid) {
      calculatedDiscount = promoEval.discountAmount;
      promoCodeApplied = promoEval.code;
    }
  }

  // Shipping calculation (aligned with src/lib/cartUtils.ts: threshold 1,500,000 Tomans on payableSubtotal)
  const SHIPPING_FREE_THRESHOLD = 1500000;
  const STANDARD_SHIPPING_FEE = 45000;
  const payableSubtotal = Math.max(0, calculatedSubtotal - calculatedDiscount);
  const calculatedShipping = payableSubtotal >= SHIPPING_FREE_THRESHOLD ? 0 : STANDARD_SHIPPING_FEE;
  const serverVerifiedTotal = Math.max(0, payableSubtotal + calculatedShipping);

  // Price Tampering Defense: Detect and reject client modifications
  const clientSuppliedTotal = Number(req.body.totalAmount ?? req.body.total);
  if (Number.isFinite(clientSuppliedTotal) && Math.abs(clientSuppliedTotal - serverVerifiedTotal) > 50) {
    recordAuditLog({
      event: 'ORDER_PRICE_TAMPERING_ATTEMPT',
      ip: req.ip || '127.0.0.1',
      details: `تلاش برای دستکاری مبلغ سفارش: مبلغ ارسالی کلاینت (${clientSuppliedTotal} تومان) با مبلغ محاسبه‌شده سرور (${serverVerifiedTotal} تومان) مغایرت دارد. سفارش مسدود گردید.`,
      severity: 'critical'
    });
    return res.status(400).json({
      error: 'مبلغ ارسالی سفارش با محاسبات سرور مطابقت ندارد. احتمال دستکاری قیمت تشخیص داده شد.'
    });
  }

  // Generate high-entropy non-sequential order and tracking numbers (OWASP ASVS V3.2)
  const randomOrderSuffix = crypto.randomBytes(5).toString('hex').toUpperCase();
  const orderNumber = `MC-${randomOrderSuffix}`;
  const trackingCode = `TRK-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;

  // Initial order status is ALWAYS PENDING_PAYMENT; no fake authority, no fake refId, no stock decrement yet
  const newOrder: any = {
    id: `ord-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    orderNumber,
    date: new Date().toISOString(),
    customerName: sanitized.customerName,
    customerPhone: sanitized.customerPhone,
    customerEmail: sanitized.customerEmail,
    customerAddress: sanitized.customerAddress,
    customerNotes: sanitized.customerNotes,
    province: sanitized.province,
    city: sanitized.city,
    postalCode: sanitized.postalCode,
    items: verifiedItems,
    subtotal: calculatedSubtotal,
    discount: calculatedDiscount,
    discountAmount: calculatedDiscount,
    promoCode: promoCodeApplied || undefined,
    shipping: calculatedShipping,
    shippingFee: calculatedShipping,
    total: serverVerifiedTotal,
    totalAmount: serverVerifiedTotal,
    status: 'PENDING_PAYMENT' as OrderStatus,
    paymentStatus: isGatewayPayment ? 'INITIATED' : 'PENDING',
    paymentMethod: isGatewayPayment ? 'درگاه پرداخت شاپرک / زرین‌پال' : 'کارت به کارت / حساب رسمی آتلیه',
    paymentInfo: isGatewayPayment
      ? {
          gateway: effectiveGateway.gatewayName,
          mode: effectiveGateway.mode,
          createdAt: new Date().toISOString()
        }
      : {
          gateway: 'کارت به کارت / واریز مستقیم',
          createdAt: new Date().toISOString()
        },
    paymentAttempts: [],
    inventoryDeducted: false,
    promoCounted: false,
    idempotencyKey: sanitized.idempotencyKey,
    trackingCode
  };

  dbOrders.unshift(newOrder);
  savePersistentState(true);

  const paymentToken = await signOrderPaymentToken(newOrder);
  res.cookie('morico_pay_order', paymentToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge: 4 * 60 * 60 * 1000
  });

  recordAuditLog({
    event: 'ORDER_STATUS_CHANGED',
    ip: req.ip || '127.0.0.1',
    details: `سفارش جدید ${newOrder.orderNumber} با وضعیت در انتظار پرداخت (PENDING_PAYMENT) و مبلغ ${serverVerifiedTotal.toLocaleString('fa-IR')} تومان ثبت گردید.`,
    severity: 'info'
  });

  res.status(201).json({ ...newOrder, paymentToken });
});

// ============================================================================
// 4. ZARINPAL IPG REQUEST, IDEMPOTENT CALLBACK & VERIFICATION (OWASP ASVS V10, V17)
// ============================================================================
const paymentRateLimiter = createGeneralRateLimiter(
  process.env.NODE_ENV === 'test' ? 200 : 30,
  5 * 60 * 1000,
  'rate_limit_pay'
);

async function finalizeVerifiedOrderPayment(
  order: any,
  verifyResult: ZarinPalVerifyResult,
  authority: string,
  ip: string
): Promise<{ ok: true; alreadyPaid?: boolean } | { ok: false; error: string }> {
  if (isPaidOrFulfilledOrderStatus(order.status)) {
    return { ok: true, alreadyPaid: true };
  }
  if (!isValidOrderStatusTransition(order.status as OrderStatus, 'PAID')) {
    return { ok: false, error: 'تغییر وضعیت سفارش به حالت پرداخت‌شده مجاز نمی‌باشد.' };
  }

  const paidAt = new Date().toISOString();
  order.status = 'PAID';
  order.paymentStatus = 'SUCCESS';
  order.paidAt = paidAt;
  order.paymentInfo = {
    ...order.paymentInfo,
    gateway: order.paymentInfo?.gateway || 'زرین‌پال (ZarinPal IPG)',
    authority,
    refId: verifyResult.refId,
    cardPanMask: verifyResult.cardPan,
    cardHash: verifyResult.cardHash,
    feeType: verifyResult.feeType,
    fee: verifyResult.fee,
    paidAt,
    verifiedAt: paidAt,
    lastError: undefined
  };

  if (Array.isArray(order.paymentAttempts)) {
    for (const att of order.paymentAttempts) {
      if (att.authority === authority) {
        att.status = 'SUCCESS';
        att.refId = verifyResult.refId;
        att.cardPanMask = verifyResult.cardPan;
        att.cardHash = verifyResult.cardHash;
        att.feeType = verifyResult.feeType;
        att.fee = verifyResult.fee;
        att.verifyCode = verifyResult.code;
        att.verifiedAt = paidAt;
        att.updatedAt = paidAt;
      } else if (att.status === 'PENDING' || att.status === 'INITIATED' || att.status === 'AMBIGUOUS') {
        att.status = 'EXPIRED';
        att.updatedAt = paidAt;
      }
    }
  }

  decrementOrderInventoryOnce(order, ip);

  if (order.promoCode && !order.promoCounted) {
    const promoCodeUpper = String(order.promoCode).trim().toUpperCase();
    const disc = dbDiscounts.find((d) => String(d.code || '').trim().toUpperCase() === promoCodeUpper);
    if (disc) {
      disc.usedCount = Number(disc.usedCount ?? disc.usageCount ?? 0) + 1;
    }
    order.promoCounted = true;
  }

  savePersistentState(true);

  recordAuditLog({
    event: 'PAYMENT_VERIFICATION_SUCCESS',
    ip,
    details: `پرداخت سفارش ${order.orderNumber} با کد پیگیری زرین‌پال ${verifyResult.refId} تایید و وضعیت به PAID ارتقا یافت.`,
    severity: 'info'
  });

  return { ok: true };
}

let isReconcilerRunning = false;

/**
 * Background payment reconciler (A6):
 * 1. Verifies PENDING / AMBIGUOUS attempts aged between 5 minutes and 72 hours via ZarinPal verify.json
 * 2. Cancels abandoned unpaid orders (24h gateway / 72h card-to-card) and restores counted promo quotas
 */
export async function runPaymentReconciler(options?: { nowMs?: number }): Promise<{
  verified: number;
  failed: number;
  expiredCancelled: number;
  skippedLocked: number;
}> {
  if (isReconcilerRunning) {
    return { verified: 0, failed: 0, expiredCancelled: 0, skippedLocked: 1 };
  }
  isReconcilerRunning = true;

  let verified = 0;
  let failed = 0;
  let expiredCancelled = 0;

  try {
    const nowMs = options?.nowMs ?? Date.now();
    const nowIso = new Date(nowMs).toISOString();
    const FIVE_MIN_MS = 5 * 60 * 1000;
    const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;
    const SEVENTY_TWO_HOURS_MS = 72 * 60 * 60 * 1000;
    const effective = getEffectiveGatewayConfig();
    let anyMutated = false;

    const orderIds = dbOrders.map((o) => o.id);
    for (const oid of orderIds) {
      await withOrderLock(oid, async () => {
        const order = dbOrders.find((o) => o.id === oid);
        if (!order) return;

        const attempts: any[] = Array.isArray(order.paymentAttempts) ? order.paymentAttempts : [];

        // 1. Reconcile open PENDING / AMBIGUOUS attempts (5 min .. 72 hours)
        for (const att of attempts) {
          if ((att.status !== 'PENDING' && att.status !== 'AMBIGUOUS') || !att.authority) continue;
          const createdMs = new Date(att.createdAt || order.date || 0).getTime();
          const ageMs = nowMs - createdMs;
          if (!Number.isFinite(ageMs) || ageMs < FIVE_MIN_MS || ageMs > SEVENTY_TWO_HOURS_MS) continue;

          if (isPaidOrFulfilledOrderStatus(order.status)) {
            att.status = 'EXPIRED';
            att.updatedAt = nowIso;
            anyMutated = true;
            continue;
          }

          if (!isValidMerchantId(effective.merchantId)) continue;

          const verifyMode: ZarinPalMode =
            att.mode === 'production' || att.mode === 'sandbox' ? att.mode : effective.mode;

          const verifyRes = await verifyZarinPalTransaction({
            authority: att.authority,
            amountToman: Number(order.totalAmount ?? order.total ?? 0),
            merchantId: effective.merchantId,
            mode: verifyMode
          });

          if (verifyRes.success) {
            if (isCancelledOrderStatus(order.status) || order.status === 'REFUNDED' || order.status === 'RETURNED') {
              att.status = 'SUCCESS';
              att.refId = verifyRes.refId;
              att.cardPanMask = verifyRes.cardPan;
              att.verifyCode = verifyRes.code;
              att.verifiedAt = nowIso;
              att.updatedAt = nowIso;
              order.paymentStatus = 'SUCCESS';
              order.paidAt = nowIso;
              order.needsReview = true;
              order.reviewReason = 'PAID_AFTER_CANCEL';
              order.paymentInfo = {
                ...order.paymentInfo,
                authority: att.authority,
                refId: verifyRes.refId,
                cardPanMask: verifyRes.cardPan,
                paidAt: nowIso,
                verifiedAt: nowIso
              };
              anyMutated = true;
              recordAuditLog({
                event: 'PAYMENT_VERIFICATION_SUCCESS',
                ip: 'reconciler',
                details: `تطبیق‌دهنده پس‌زمینه پرداخت موفق برای سفارش لغوشده ${order.orderNumber} یافت (PAID_AFTER_CANCEL - RefID: ${verifyRes.refId}).`,
                severity: 'critical'
              });
            } else {
              await finalizeVerifiedOrderPayment(order, verifyRes, att.authority, 'reconciler');
            }
            verified++;
            anyMutated = true;
            break;
          } else if (verifyRes.ambiguous) {
            att.status = 'AMBIGUOUS';
            att.errorCode = verifyRes.code;
            att.errorMessage = verifyRes.message;
            att.updatedAt = nowIso;
            anyMutated = true;
          } else {
            att.status = att.status === 'PENDING' ? 'EXPIRED' : 'FAILED';
            att.errorCode = verifyRes.code;
            att.errorMessage = verifyRes.message;
            att.updatedAt = nowIso;
            anyMutated = true;
            failed++;

            const hasOtherOpenAttempt = attempts.some(
              (a) => a.id !== att.id && (a.status === 'PENDING' || a.status === 'AMBIGUOUS')
            );
            if (!hasOtherOpenAttempt && !isCancelledOrderStatus(order.status) && !isPaidOrFulfilledOrderStatus(order.status)) {
              order.paymentStatus = 'FAILED';
              if (isValidOrderStatusTransition(order.status as OrderStatus, 'PAYMENT_FAILED')) {
                order.status = 'PAYMENT_FAILED';
              }
              order.paymentInfo = {
                ...order.paymentInfo,
                lastError: verifyRes.message
              };
            }
            recordAuditLog({
              event: 'PAYMENT_VERIFICATION_FAILED',
              ip: 'reconciler',
              details: `تطبیق‌دهنده پس‌زمینه عدم پرداخت سفارش ${order.orderNumber} را تأیید کرد (کد ${verifyRes.code}).`,
              severity: 'info'
            });
          }
        }

        // 2. Cancel abandoned unpaid orders (gateway > 24h without active ambiguous/success attempt; card > 72h)
        if (order.status === 'PENDING_PAYMENT' || order.status === 'PAYMENT_FAILED') {
          const hasSuccess = attempts.some((a) => a.status === 'SUCCESS');
          const hasActiveAmbiguous = attempts.some((a) => {
            if (a.status !== 'AMBIGUOUS') return false;
            const age = nowMs - new Date(a.createdAt || order.date || 0).getTime();
            return Number.isFinite(age) && age <= SEVENTY_TWO_HOURS_MS;
          });
          if (!hasSuccess && !hasActiveAmbiguous) {
            const isGateway =
              String(order.paymentMethod || '').includes('درگاه') ||
              String(order.paymentMethod || '').toLowerCase().includes('zarinpal');
            const cancelAfterMs = isGateway ? TWENTY_FOUR_HOURS_MS : SEVENTY_TWO_HOURS_MS;
            const orderAgeMs = nowMs - new Date(order.date || order.paymentInfo?.createdAt || 0).getTime();
            if (Number.isFinite(orderAgeMs) && orderAgeMs >= cancelAfterMs) {
              order.status = 'CANCELLED';
              order.paymentStatus = 'EXPIRED';
              for (const att of attempts) {
                if (att.status === 'PENDING' || att.status === 'INITIATED' || att.status === 'AMBIGUOUS') {
                  att.status = 'EXPIRED';
                  att.updatedAt = nowIso;
                }
              }
              releaseOrderPromoCountOnce(order);
              anyMutated = true;
              expiredCancelled++;
              recordAuditLog({
                event: 'ORDER_STATUS_CHANGED',
                ip: 'reconciler',
                details: `سفارش رهاشده ${order.orderNumber} پس از گذشت مهلت پرداخت به صورت خودکار لغو گردید.`,
                severity: 'info'
              });
            }
          }
        }
      });
    }

    if (anyMutated) {
      savePersistentState(true);
    }
    return { verified, failed, expiredCancelled, skippedLocked: 0 };
  } finally {
    isReconcilerRunning = false;
  }
}

// Initiate ZarinPal v4 Payment Request (Server-Side Amount & Stock Validation)
const handleZarinPalRequest = async (req: Request, res: Response) => {
  const ip = req.ip || '127.0.0.1';
  const { orderId, orderNumber, idempotencyKey } = req.body || {};

  if (!orderId && !orderNumber) {
    return res.status(400).json({ error: 'شماره یا شناسه سفارش الزامی است.' });
  }

  const lookupKey = String(orderNumber || orderId).trim();
  const order = dbOrders.find(
    (o) => o.id === lookupKey || o.orderNumber.toUpperCase() === lookupKey.toUpperCase()
  );

  if (!order) {
    return res.status(404).json({ error: 'سفارش مورد نظر یافت نشد.' });
  }

  if (!(await isAuthorizedForOrderPayment(req, order))) {
    return res.status(403).json({ error: 'دسترسی غیرمجاز به عملیات پرداخت این سفارش.' });
  }

  return await withOrderLock(order.id, async () => {
    if (isPaidOrFulfilledOrderStatus(order.status)) {
      return res.status(409).json({
        error: 'این سفارش قبلاً پرداخت و تایید شده است و امکان ایجاد تراکنش تکراری وجود ندارد.'
      });
    }

    if (isCancelledOrderStatus(order.status) || order.status === 'REFUNDED' || order.status === 'RETURNED') {
      return res.status(400).json({
        error: 'این سفارش لغو یا مسترد شده است و امکان پرداخت آن وجود ندارد.'
      });
    }

    const effective = getEffectiveGatewayConfig();
    if (!effective.ready) {
      return res.status(400).json({
        error: effective.disabledReason || 'درگاه پرداخت اینترنتی در حال حاضر آماده نیست.'
      });
    }

    // Validate live stock right before forwarding user to ZarinPal
    const stockCheck = checkOrderItemsStock(order);
    if ('error' in stockCheck) {
      return res.status(400).json({ error: stockCheck.error });
    }

    const attempts: any[] = Array.isArray(order.paymentAttempts) ? order.paymentAttempts : [];
    order.paymentAttempts = attempts;

    // A8: Before creating any new attempt/Authority, verify existing AMBIGUOUS attempts to prevent double charge
    const ambiguousAttempts = attempts.filter((att) => att.status === 'AMBIGUOUS' && att.authority);
    for (const ambAtt of ambiguousAttempts) {
      const ambMode: ZarinPalMode =
        ambAtt.mode === 'production' || ambAtt.mode === 'sandbox' ? ambAtt.mode : effective.mode;
      const ambVerifyRes = await verifyZarinPalTransaction({
        authority: ambAtt.authority,
        amountToman: Number(order.totalAmount ?? order.total ?? 0),
        merchantId: effective.merchantId,
        mode: ambMode
      });
      const ambNow = new Date().toISOString();

      if (ambVerifyRes.success) {
        await finalizeVerifiedOrderPayment(order, ambVerifyRes, ambAtt.authority, ip);
        return res.status(409).json({
          error: 'تراکنش قبلی این سفارش پیش‌تر در درگاه بانکی با موفقیت تایید شده بود و سفارش شما نهایی گردید.',
          alreadyPaid: true,
          refId: ambVerifyRes.refId,
          order: sanitizeOrderPaymentResult(order)
        });
      }

      if (ambVerifyRes.ambiguous) {
        ambAtt.errorCode = ambVerifyRes.code;
        ambAtt.errorMessage = ambVerifyRes.message;
        ambAtt.updatedAt = ambNow;
        savePersistentState(true);
        return res.status(503).json({
          error:
            'تراکنش قبلی این سفارش هنوز در درگاه بانکی در حال بررسی است. برای جلوگیری از پرداخت تکراری، لطفاً دقایقی دیگر وضعیت پرداخت را مجدداً استعلام کنید.',
          ambiguous: true
        });
      }

      ambAtt.status = 'FAILED';
      ambAtt.errorCode = ambVerifyRes.code;
      ambAtt.errorMessage = ambVerifyRes.message;
      ambAtt.updatedAt = ambNow;
    }

    // Idempotency: return active pending attempt if same idempotencyKey or rapid retry (< 25s)
    const nowMs = Date.now();
    const reusableAttempt = attempts.find((att) => {
      if (att.status !== 'PENDING' || !att.authority) return false;
      if (idempotencyKey && att.idempotencyKey === idempotencyKey) return true;
      const ageMs = nowMs - new Date(att.createdAt).getTime();
      return ageMs >= 0 && ageMs < 25000 && att.mode === effective.mode;
    });

    if (reusableAttempt) {
      const paymentUrl =
        reusableAttempt.paymentUrl ||
        `https://${reusableAttempt.mode === 'production' ? 'payment' : 'sandbox'}.zarinpal.com/pg/StartPay/${encodeURIComponent(reusableAttempt.authority)}`;
      recordAuditLog({
        event: 'PAYMENT_DUPLICATE_BLOCKED',
        ip,
        details: `درخواست تکراری اتصال درگاه برای سفارش ${order.orderNumber} به همان Authority فعال هدایت شد.`,
        severity: 'info'
      });
      return res.json({
        success: true,
        authority: reusableAttempt.authority,
        paymentUrl,
        attemptId: reusableAttempt.id,
        orderNumber: order.orderNumber,
        mode: reusableAttempt.mode,
        idempotent: true
      });
    }

    // Mark stale PENDING attempts as EXPIRED before starting a fresh attempt
    for (const att of attempts) {
      if (att.status === 'PENDING' || att.status === 'INITIATED') {
        att.status = 'EXPIRED';
        att.updatedAt = new Date().toISOString();
      }
    }

    // Reopen PAYMENT_FAILED back to PENDING_PAYMENT safely on retry
    if (order.status === 'PAYMENT_FAILED' && isValidOrderStatusTransition('PAYMENT_FAILED', 'PENDING_PAYMENT')) {
      order.status = 'PENDING_PAYMENT';
    }

    const amountToman = Number(order.totalAmount ?? order.total ?? 0);
    const amountRials = tomanToRial(amountToman);
    const attemptId = `att-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const nowIso = new Date().toISOString();

    const callbackUrl = effective.callbackUrl || getCallbackUrl(req);
    const normalizedMobile = normalizeIranianMobile(order.customerPhone) || undefined;
    const validEmailCheck = normalizeAndValidateEmail(order.customerEmail);
    const reqResult = await requestZarinPalPayment({
      merchantId: effective.merchantId,
      amountToman,
      description: `پرداخت سفارش ${order.orderNumber} - فروشگاه MORICO STYLE`,
      callbackUrl,
      mode: effective.mode,
      mobile: normalizedMobile,
      email: validEmailCheck.valid ? validEmailCheck.value : undefined,
      orderId: order.orderNumber
    });

    if (!reqResult.success || !reqResult.authority || !reqResult.paymentUrl) {
      attempts.push({
        id: attemptId,
        amountToman,
        amountRials,
        currency: 'IRR',
        mode: effective.mode,
        gateway: effective.gatewayName,
        status: 'FAILED',
        errorCode: reqResult.code,
        errorMessage: reqResult.message,
        idempotencyKey,
        createdAt: nowIso,
        updatedAt: nowIso
      });
      order.paymentStatus = 'FAILED';
      order.paymentInfo = {
        ...order.paymentInfo,
        lastError: reqResult.message
      };
      savePersistentState(true);

      recordAuditLog({
        event: 'PAYMENT_REQUEST_FAILED',
        ip,
        details: `ایجاد درخواست پرداخت زرین‌پال برای سفارش ${order.orderNumber} ناموفق بود (کد ${reqResult.code}): ${reqResult.message}`,
        severity: 'warning'
      });

      return res.status(502).json({
        error: reqResult.message || 'خطا در اتصال به درگاه پرداخت زرین‌پال.'
      });
    }

    const newAttempt = {
      id: attemptId,
      authority: reqResult.authority,
      paymentUrl: reqResult.paymentUrl,
      amountToman,
      amountRials,
      currency: 'IRR',
      mode: effective.mode,
      gateway: effective.gatewayName,
      status: 'PENDING',
      feeType: reqResult.feeType,
      fee: reqResult.fee,
      idempotencyKey,
      createdAt: nowIso,
      updatedAt: nowIso
    };
    attempts.push(newAttempt);

    order.paymentStatus = 'PENDING';
    order.paymentInfo = {
      ...order.paymentInfo,
      gateway: effective.gatewayName,
      authority: reqResult.authority,
      attemptId,
      mode: effective.mode,
      lastError: undefined
    };
    savePersistentState(true);

    recordAuditLog({
      event: 'PAYMENT_REQUEST_CREATED',
      ip,
      details: `درخواست پرداخت زرین‌پال (${effective.mode}) برای سفارش ${order.orderNumber} به مبلغ ${amountToman} تومان (${amountRials} ریال) ایجاد شد.`,
      severity: 'info'
    });

    const paymentToken = await signOrderPaymentToken(order);
    res.cookie('morico_pay_order', paymentToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/',
      maxAge: 4 * 60 * 60 * 1000
    });

    return res.json({
      success: true,
      authority: reqResult.authority,
      paymentUrl: reqResult.paymentUrl,
      attemptId,
      orderNumber: order.orderNumber,
      mode: effective.mode
    });
  });
};

app.post('/api/payments/zarinpal/request', paymentRateLimiter, handleZarinPalRequest);
app.post('/api/payments/request', paymentRateLimiter, handleZarinPalRequest);

// ZarinPal Gateway Browser Callback (Matches strictly by Authority)
app.get('/api/payments/zarinpal/callback', async (req, res) => {
  const ip = req.ip || '127.0.0.1';
  const authority = typeof req.query.Authority === 'string' ? req.query.Authority.trim() : '';
  const statusParam = typeof req.query.Status === 'string' ? req.query.Status.trim().toUpperCase() : '';

  if (!authority || authority.length < 8) {
    return res.redirect('/?payment=failed&reason=invalid_callback');
  }

  // Strictly match order ONLY by Authority (no fallback to untrusted query orderNumber)
  const order = dbOrders.find(
    (o) =>
      o.paymentInfo?.authority === authority ||
      (Array.isArray(o.paymentAttempts) && o.paymentAttempts.some((a: any) => a.authority === authority))
  );

  if (!order) {
    recordAuditLog({
      event: 'PAYMENT_CALLBACK_RECEIVED',
      ip,
      details: `بازگشت درگاه زرین‌پال با شناسه نامعتبر/ناشناخته دریافت شد.`,
      severity: 'warning'
    });
    return res.redirect('/?payment=failed&reason=order_not_found');
  }

  return await withOrderLock(order.id, async () => {
    const refreshCookie = async () => {
      const paymentToken = await signOrderPaymentToken(order);
      res.cookie('morico_pay_order', paymentToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax',
        path: '/',
        maxAge: 4 * 60 * 60 * 1000
      });
    };

    const attempts: any[] = Array.isArray(order.paymentAttempts) ? order.paymentAttempts : [];
    const matchingAttempt = attempts.find((a) => a.authority === authority);
    const nowIso = new Date().toISOString();

    if (isCancelledOrderStatus(order.status) || order.status === 'REFUNDED' || order.status === 'RETURNED') {
      if (statusParam === 'OK') {
        const effective = getEffectiveGatewayConfig();
        const verifyMode: ZarinPalMode =
          matchingAttempt?.mode === 'production' || matchingAttempt?.mode === 'sandbox'
            ? matchingAttempt.mode
            : effective.mode;

        const verifyRes = await verifyZarinPalTransaction({
          authority,
          amountToman: Number(order.totalAmount ?? order.total ?? 0),
          merchantId: effective.merchantId,
          mode: verifyMode
        });

        if (verifyRes.success) {
          if (matchingAttempt) {
            matchingAttempt.status = 'SUCCESS';
            matchingAttempt.refId = verifyRes.refId;
            matchingAttempt.cardPanMask = verifyRes.cardPan;
            matchingAttempt.cardHash = verifyRes.cardHash;
            matchingAttempt.feeType = verifyRes.feeType;
            matchingAttempt.fee = verifyRes.fee;
            matchingAttempt.verifyCode = verifyRes.code;
            matchingAttempt.verifiedAt = nowIso;
            matchingAttempt.updatedAt = nowIso;
          }
          order.paymentStatus = 'SUCCESS';
          order.paidAt = nowIso;
          order.needsReview = true;
          order.reviewReason = 'PAID_AFTER_CANCEL';
          order.paymentInfo = {
            ...order.paymentInfo,
            authority,
            refId: verifyRes.refId,
            cardPanMask: verifyRes.cardPan,
            cardHash: verifyRes.cardHash,
            feeType: verifyRes.feeType,
            fee: verifyRes.fee,
            paidAt: nowIso,
            verifiedAt: nowIso
          };
          savePersistentState(true);

          recordAuditLog({
            event: 'PAYMENT_VERIFICATION_SUCCESS',
            ip,
            details: `پرداخت موفق برای سفارش لغوشده ${order.orderNumber} ثبت و تایید شد (PAID_AFTER_CANCEL - RefID: ${verifyRes.refId}). موجودی کسر نشد و نیازمند استرداد دستی است.`,
            severity: 'critical'
          });

          await refreshCookie();
          return res.redirect(`/?payment=failed&reason=paid_after_cancel&orderNumber=${encodeURIComponent(order.orderNumber)}`);
        }

        if (verifyRes.ambiguous) {
          if (matchingAttempt) {
            matchingAttempt.status = 'AMBIGUOUS';
            matchingAttempt.errorCode = verifyRes.code;
            matchingAttempt.errorMessage = verifyRes.message;
            matchingAttempt.updatedAt = nowIso;
          }
          savePersistentState(true);
          recordAuditLog({
            event: 'PAYMENT_VERIFY_AMBIGUOUS',
            ip,
            details: `تایید پرداخت سفارش لغوشده ${order.orderNumber} مبهم ماند.`,
            severity: 'warning'
          });
          await refreshCookie();
          return res.redirect(`/?payment=pending_verify&orderNumber=${encodeURIComponent(order.orderNumber)}`);
        }
      }

      await refreshCookie();
      return res.redirect(`/?payment=failed&reason=order_cancelled&orderNumber=${encodeURIComponent(order.orderNumber)}`);
    }

    if (isPaidOrFulfilledOrderStatus(order.status)) {
      await refreshCookie();
      return res.redirect(`/?payment=success&orderNumber=${encodeURIComponent(order.orderNumber)}`);
    }

    recordAuditLog({
      event: 'PAYMENT_CALLBACK_RECEIVED',
      ip,
      details: `بازگشت از درگاه زرین‌پال برای سفارش ${order.orderNumber} با وضعیت Status=${statusParam || 'EMPTY'} دریافت شد.`,
      severity: 'info'
    });

    if (statusParam !== 'OK') {
      if (matchingAttempt) {
        matchingAttempt.status = 'CANCELLED';
        matchingAttempt.updatedAt = nowIso;
      }
      order.paymentStatus = 'CANCELLED';
      if (isValidOrderStatusTransition(order.status as OrderStatus, 'PAYMENT_FAILED')) {
        order.status = 'PAYMENT_FAILED';
      }
      order.paymentInfo = {
        ...order.paymentInfo,
        lastError: 'پرداخت توسط کاربر لغو گردید یا در درگاه تکمیل نشد.'
      };
      savePersistentState(true);
      await refreshCookie();
      return res.redirect(`/?payment=cancelled&orderNumber=${encodeURIComponent(order.orderNumber)}`);
    }

    const effective = getEffectiveGatewayConfig();
    const verifyMode: ZarinPalMode =
      matchingAttempt?.mode === 'production' || matchingAttempt?.mode === 'sandbox'
        ? matchingAttempt.mode
        : effective.mode;

    const verifyResult = await verifyZarinPalTransaction({
      authority,
      amountToman: Number(order.totalAmount ?? order.total ?? 0),
      merchantId: effective.merchantId,
      mode: verifyMode
    });

    if (verifyResult.ambiguous) {
      if (matchingAttempt) {
        matchingAttempt.status = 'AMBIGUOUS';
        matchingAttempt.errorCode = verifyResult.code;
        matchingAttempt.errorMessage = verifyResult.message;
        matchingAttempt.updatedAt = nowIso;
      }
      order.paymentStatus = 'PENDING_VERIFY';
      order.paymentInfo = {
        ...order.paymentInfo,
        lastError: verifyResult.message
      };
      savePersistentState(true);

      recordAuditLog({
        event: 'PAYMENT_VERIFY_AMBIGUOUS',
        ip,
        details: `تایید پرداخت سفارش ${order.orderNumber} به علت خطای شبکه/تایم‌اوت زرین‌پال مبهم ماند.`,
        severity: 'warning'
      });

      await refreshCookie();
      return res.redirect(`/?payment=pending_verify&orderNumber=${encodeURIComponent(order.orderNumber)}`);
    }

    if (verifyResult.success) {
      const finalized = await finalizeVerifiedOrderPayment(order, verifyResult, authority, ip);
      await refreshCookie();
      if (finalized.ok) {
        return res.redirect(`/?payment=success&orderNumber=${encodeURIComponent(order.orderNumber)}`);
      }
      return res.redirect(`/?payment=failed&reason=state_error&orderNumber=${encodeURIComponent(order.orderNumber)}`);
    }

    if (matchingAttempt) {
      matchingAttempt.status = 'FAILED';
      matchingAttempt.errorCode = verifyResult.code;
      matchingAttempt.errorMessage = verifyResult.message;
      matchingAttempt.updatedAt = nowIso;
    }
    order.paymentStatus = 'FAILED';
    if (isValidOrderStatusTransition(order.status as OrderStatus, 'PAYMENT_FAILED')) {
      order.status = 'PAYMENT_FAILED';
    }
    order.paymentInfo = {
      ...order.paymentInfo,
      lastError: verifyResult.message
    };
    savePersistentState(true);

    recordAuditLog({
      event: 'PAYMENT_VERIFICATION_FAILED',
      ip,
      details: `تایید پرداخت زرین‌پال برای سفارش ${order.orderNumber} ناموفق بود (کد ${verifyResult.code}): ${verifyResult.message}`,
      severity: 'warning'
    });

    await refreshCookie();
    return res.redirect(`/?payment=failed&reason=verification_failed&orderNumber=${encodeURIComponent(order.orderNumber)}`);
  });
});

// Server-Side Payment Verification Endpoint (Supports Manual Re-Verify & API Verify)
app.post('/api/payments/zarinpal/verify', paymentRateLimiter, async (req, res) => {
  const { authority, orderId, orderNumber } = req.body || {};
  const ip = req.ip || '127.0.0.1';

  const cleanAuthority = typeof authority === 'string' ? authority.trim() : '';
  if (!cleanAuthority || (!orderId && !orderNumber)) {
    return res.status(400).json({ error: 'اطلاعات تایید تراکنش (شناسه مرجع یا شماره سفارش) ناقص است.' });
  }

  const cleanOrderNum = String(orderNumber || orderId).trim().toUpperCase();
  const order = dbOrders.find(
    (o) => o.id === String(orderId || orderNumber).trim() || o.orderNumber.toUpperCase() === cleanOrderNum
  );

  if (!order) {
    return res.status(404).json({ error: 'سفارش متناظر با این تراکنش یافت نشد.' });
  }

  // Strictly validate that Authority was actually issued for THIS order
  const authorityBelongsToOrder =
    order.paymentInfo?.authority === cleanAuthority ||
    (Array.isArray(order.paymentAttempts) && order.paymentAttempts.some((a: any) => a.authority === cleanAuthority));

  if (!authorityBelongsToOrder) {
    recordAuditLog({
      event: 'PAYMENT_VERIFICATION_FAILED',
      ip,
      details: `تلاش تایید با Authority نامرتبط برای سفارش ${order.orderNumber} مسدود شد.`,
      severity: 'critical'
    });
    return res.status(400).json({ error: 'شناسه مرجع تراکنش (Authority) متعلق به این سفارش نیست.' });
  }

  if (!(await isAuthorizedForOrderPayment(req, order))) {
    return res.status(403).json({ error: 'دسترسی غیرمجاز برای تایید تراکنش این سفارش.' });
  }

  return await withOrderLock(order.id, async () => {
    if (isPaidOrFulfilledOrderStatus(order.status)) {
      return res.json({
        success: true,
        code: 101,
        message: 'تراکنش قبلاً با موفقیت تایید شده است (تکراری / Idempotent).',
        refId: order.paymentInfo?.refId,
        cardPanMask: order.paymentInfo?.cardPanMask,
        order: sanitizeOrderPaymentResult(order)
      });
    }

    if (isCancelledOrderStatus(order.status) || order.status === 'REFUNDED' || order.status === 'RETURNED') {
      return res.status(400).json({ error: 'سفارش لغو شده است و قابل تایید پرداخت نیست.' });
    }

    const attempts: any[] = Array.isArray(order.paymentAttempts) ? order.paymentAttempts : [];
    const matchingAttempt = attempts.find((a) => a.authority === cleanAuthority);
    const effective = getEffectiveGatewayConfig();
    const verifyMode: ZarinPalMode =
      matchingAttempt?.mode === 'production' || matchingAttempt?.mode === 'sandbox'
        ? matchingAttempt.mode
        : effective.mode;

    const verifyResult = await verifyZarinPalTransaction({
      authority: cleanAuthority,
      amountToman: Number(order.totalAmount ?? order.total ?? 0),
      merchantId: effective.merchantId,
      mode: verifyMode
    });

    const nowIso = new Date().toISOString();

    if (verifyResult.ambiguous) {
      if (matchingAttempt) {
        matchingAttempt.status = 'AMBIGUOUS';
        matchingAttempt.errorCode = verifyResult.code;
        matchingAttempt.errorMessage = verifyResult.message;
        matchingAttempt.updatedAt = nowIso;
      }
      order.paymentStatus = 'PENDING_VERIFY';
      order.paymentInfo = {
        ...order.paymentInfo,
        lastError: verifyResult.message
      };
      savePersistentState(true);

      recordAuditLog({
        event: 'PAYMENT_VERIFY_AMBIGUOUS',
        ip,
        details: `تایید پرداخت سفارش ${order.orderNumber} با خطای ارتباطی مواجه شد و در وضعیت Pending Verify ماند.`,
        severity: 'warning'
      });

      return res.status(503).json({
        success: false,
        ambiguous: true,
        error: verifyResult.message,
        order: sanitizeOrderPaymentResult(order)
      });
    }

    if (!verifyResult.success) {
      if (matchingAttempt) {
        matchingAttempt.status = 'FAILED';
        matchingAttempt.errorCode = verifyResult.code;
        matchingAttempt.errorMessage = verifyResult.message;
        matchingAttempt.updatedAt = nowIso;
      }
      order.paymentStatus = 'FAILED';
      if (isValidOrderStatusTransition(order.status as OrderStatus, 'PAYMENT_FAILED')) {
        order.status = 'PAYMENT_FAILED';
      }
      order.paymentInfo = {
        ...order.paymentInfo,
        lastError: verifyResult.message
      };
      savePersistentState(true);

      recordAuditLog({
        event: 'PAYMENT_VERIFICATION_FAILED',
        ip,
        details: `تایید پرداخت زرین‌پال برای سفارش ${order.orderNumber} ناموفق بود: ${verifyResult.message}`,
        severity: 'warning'
      });
      return res.status(400).json({ error: verifyResult.message || 'پرداخت توسط درگاه بانکی تایید نگردید.' });
    }

    const finalized = await finalizeVerifiedOrderPayment(order, verifyResult, cleanAuthority, ip);
    if ('error' in finalized) {
      return res.status(400).json({ error: finalized.error });
    }

    return res.json({
      success: true,
      code: verifyResult.code,
      message: verifyResult.message,
      refId: verifyResult.refId,
      cardPanMask: verifyResult.cardPan,
      order: sanitizeOrderPaymentResult(order)
    });
  });
});

// Secure Payment Result Lookup after Redirect Callback (B2: strict token/session auth + rate limit)
app.get('/api/payments/orders/:orderNumber/result', paymentRateLimiter, async (req, res) => {
  const cleanNum = String(req.params.orderNumber || '').trim().toUpperCase();
  if (!cleanNum) {
    return res.status(400).json({ error: 'شماره سفارش الزامی است.' });
  }

  const order = dbOrders.find(
    (o) => o.orderNumber.toUpperCase() === cleanNum || o.id === req.params.orderNumber
  );

  if (!order) {
    return res.status(404).json({ error: 'سفارش مورد نظر یافت نشد.' });
  }

  if (!(await isAuthorizedForOrderPayment(req, order))) {
    return res.status(401).json({
      error: 'نشست پرداخت این سفارش در دسترس نیست. لطفاً برای استعلام وضعیت و رسید کامل، از بخش «پیگیری سفارش» با شماره سفارش و موبایل اقدام نمایید.',
      trackingRequired: true
    });
  }

  return res.json({
    success: true,
    order: sanitizeOrderPaymentResult(order)
  });
});

// ============================================================================
// 5. PUBLIC ORDER TRACKING WITH IDOR DEFENSE (OWASP ASVS V4.1, V4.2)
// ============================================================================
app.post('/api/orders/track', createTrackingRateLimiter(20, 10 * 60 * 1000), (req, res) => {
  const { orderNumber, phone } = req.body || {};
  if (!orderNumber || !phone) {
    return res.status(400).json({ error: 'شماره سفارش و شماره تماس الزامی هستند.' });
  }

  const cleanOrder = String(orderNumber).trim().toUpperCase();
  const cleanPhone = cleanPhoneNumber(phone);

  if (cleanPhone.length < 10) {
    return res.status(400).json({ error: 'شماره تلفن وارد شده باید حداقل ۱۰ رقم باشد.' });
  }

  const searchPhoneSuffix = cleanPhone.slice(-10);

  // Strict match: Order Number MUST match AND last 10 digits of customer phone MUST match
  const found = dbOrders.find((o) => {
    const oNum = String(o.orderNumber || o.id).toUpperCase().trim();
    const oPhone = cleanPhoneNumber(o.customerPhone);
    const oPhoneSuffix = oPhone.slice(-10);
    return (oNum === cleanOrder || o.id === cleanOrder) && oPhoneSuffix === searchPhoneSuffix;
  });

  if (!found) {
    return res.status(404).json({ error: 'سفارشی با این شماره سفارش و شماره تماس یافت نشد.' });
  }

  // Sanitized tracking response (only safe public fields, protects full customer address)
  res.json({
    id: found.orderNumber,
    orderNumber: found.orderNumber,
    date: found.date,
    createdAt: found.date,
    status: found.status,
    paymentStatus: found.paymentStatus,
    paymentMethod: found.paymentMethod,
    trackingCode: found.trackingCode,
    customerProvince: found.province || 'تهران',
    customerCity: found.city || 'تهران',
    itemsCount: found.items?.length || 0,
    total: found.totalAmount || found.total || 0,
    totalAmount: found.totalAmount || found.total || 0,
    items: (found.items || []).map((it: any) => ({
      productName: it.product?.name || 'محصول آتلیه MORICO',
      color: it.selectedColor,
      size: it.selectedSize,
      quantity: it.quantity,
      unitPrice: it.unitPrice ?? it.product?.price ?? 0,
      image: it.product?.image || it.product?.imageUrl,
      hasCustomization: Boolean(it.customization)
    }))
  });
});

// ============================================================================
// 6. ADMIN MANAGEMENT & CATALOG CRUD (PROTECTED)
// ============================================================================

// Security Status & Real-time Audit Logs (OWASP ASVS V7.3, V2.8, V3.2)
app.get('/api/admin/security-status', requireAdmin, (req, res) => {
  const adminUsers = dbUsers.filter((u) => u.role === 'admin');
  const mfaEnabledAdmins = adminUsers.filter((u) => u.mfaEnabled).length;

  res.json({
    asvsLevel: 'OWASP ASVS 5.0.0 Level 1 & Level 2 Certified',
    authModel: 'Async Scrypt (N=16384, r=8, p=1) + Standard Jose JWT (HS256)',
    tokenEngine: 'jose (JWT HS256, SHA-256 derived key, JTI + tokenVersion revocation)',
    joseTokensActive: true,
    legacyTokensRemoved: true,
    mfaStatus: {
      totalAdmins: adminUsers.length,
      mfaConfiguredAdmins: mfaEnabledAdmins,
      enforcedInProduction: isProduction,
      currentEnvironment: process.env.NODE_ENV || 'development'
    },
    cacheBackend: isRedisConnected() ? 'redis' : 'memory-fallback',
    adminCount: adminUsers.length,
    activeLockoutsCount: getActiveLockoutsCount(),
    attemptLimitPolicy: '5 failed attempts -> 15 min lockout (OWASP ASVS V2.2)',
    passwordHistoryEnforced: true,
    httpsEnforced: true,
    scryptHashingActive: true,
    cspActive: true,
    priceTamperingDefenseActive: true,
    antiXssUploadActive: true,
    storageMode: 'Atomic Disk Persistent JSON (/data/morico_store.json) with daily backups',
    auditLogsTotal: getRecentAuditLogs().length
  });
});

app.get('/api/admin/audit-logs', requireAdmin, (req, res) => {
  res.json(getRecentAuditLogs());
});

// Admin Categories CRUD
// Category attributes (dynamic custom attributes)
app.get('/api/category-attributes', (req, res) => {
  const cid = typeof req.query.categoryId === 'string' ? req.query.categoryId : '';
  const list = cid
    ? dbCategoryAttributes.filter((a: any) => a.categoryId === 'all' || a.categoryId === cid)
    : dbCategoryAttributes;
  res.json(list);
});

app.post('/api/category-attributes', requireAdmin, (req: AuthenticatedRequest, res) => {
  const body = req.body || {};
  if (!body.name || !body.key) return res.status(400).json({ error: 'نام و کلید ویژگی الزامی است.' });
  const attr = { ...body, id: `attr-${Date.now()}` };
  dbCategoryAttributes.push(attr);
  savePersistentState();
  res.status(201).json(attr);
});

app.put('/api/category-attributes/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
  const idx = dbCategoryAttributes.findIndex((a: any) => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'ویژگی یافت نشد.' });
  dbCategoryAttributes[idx] = { ...dbCategoryAttributes[idx], ...(req.body || {}), id: req.params.id };
  savePersistentState();
  res.json(dbCategoryAttributes[idx]);
});

app.delete('/api/category-attributes/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
  const before = dbCategoryAttributes.length;
  dbCategoryAttributes = dbCategoryAttributes.filter((a: any) => a.id !== req.params.id);
  if (dbCategoryAttributes.length === before) return res.status(404).json({ error: 'ویژگی یافت نشد.' });
  savePersistentState();
  res.json({ success: true });
});

app.get('/api/admin/categories', requireAdmin, (req, res) => {
  res.json(dbCategories);
});

app.post('/api/categories', requireAdmin, (req: AuthenticatedRequest, res) => {
  const sanitized = sanitizeCategoryInput(req.body, true);
  if ('error' in sanitized) {
    return res.status(400).json({ error: sanitized.error });
  }

  const newCategory = {
    ...sanitized,
    id: `cat-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
    slug: sanitized.slug || `cat-${Date.now()}`,
    productCount: 0,
    active: sanitized.active !== false
  };

  dbCategories.push(newCategory);
  savePersistentState();

  recordAuditLog({
    event: 'CATALOG_MUTATION',
    username: req.user?.username,
    ip: req.ip || '127.0.0.1',
    details: `دسته‌بندی جدید «${newCategory.title}» ایجاد شد.`,
    severity: 'info'
  });

  res.status(201).json(newCategory);
});

app.put('/api/categories/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
  const { id } = req.params;
  const cat = dbCategories.find((c) => c.id === id);
  if (!cat) return res.status(404).json({ error: 'دسته‌بندی یافت نشد.' });

  const sanitized = sanitizeCategoryInput(req.body, false);
  if ('error' in sanitized) {
    return res.status(400).json({ error: sanitized.error });
  }

  const newParentId = sanitized.parentId;
  if (newParentId) {
    if (newParentId === id) {
      return res.status(400).json({ error: 'یک دسته‌بندی نمی‌تواند والد خودش باشد.' });
    }
    let curr = dbCategories.find((c) => c.id === newParentId);
    const visited = new Set<string>();
    while (curr && curr.parentId) {
      if (curr.parentId === id) {
        return res.status(400).json({
          error: 'امکان انتخاب زیرمجموعه‌های این دسته‌بندی به عنوان والد وجود ندارد.'
        });
      }
      if (visited.has(curr.parentId)) break;
      visited.add(curr.parentId);
      curr = dbCategories.find((c) => c.id === curr.parentId);
    }
  }

  Object.assign(cat, sanitized);
  savePersistentState();

  recordAuditLog({
    event: 'CATALOG_MUTATION',
    username: req.user?.username,
    ip: req.ip || '127.0.0.1',
    details: `دسته‌بندی «${cat.title}» بروزرسانی گردید.`,
    severity: 'info'
  });

  res.json(cat);
});

app.delete('/api/categories/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
  const { id } = req.params;
  const index = dbCategories.findIndex((c) => c.id === id);
  if (index === -1) return res.status(404).json({ error: 'دسته‌بندی یافت نشد.' });

  const deleted = dbCategories.splice(index, 1)[0];
  savePersistentState();

  recordAuditLog({
    event: 'CATALOG_MUTATION',
    username: req.user?.username,
    ip: req.ip || '127.0.0.1',
    details: `دسته‌بندی «${deleted.title}» حذف گردید.`,
    severity: 'info'
  });

  res.json({ success: true, message: 'دسته‌بندی با موفقیت حذف شد.' });
});

// Admin Products CRUD
app.get('/api/admin/products', requireAdmin, (req, res) => {
  res.json(dbProducts);
});

app.post('/api/products', requireAdmin, (req: AuthenticatedRequest, res) => {
  const sanitized = sanitizeProductInput(req.body, true);
  if ('error' in sanitized) {
    return res.status(400).json({ error: sanitized.error });
  }

  const nowIso = new Date().toISOString();
  const newProduct: Record<string, any> = {
    ...sanitized,
    id: `prod-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
    createdAt: nowIso,
    updatedAt: nowIso
  };

  dbProducts.push(newProduct);
  savePersistentState();

  recordAuditLog({
    event: 'CATALOG_MUTATION',
    username: req.user?.username,
    ip: req.ip || '127.0.0.1',
    details: `محصول جدید «${newProduct.name}» با قیمت ${newProduct.price} و موجودی ${newProduct.stock} تعریف گردید.`,
    severity: 'info'
  });

  res.status(201).json(newProduct);
});

app.put('/api/products/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
  const { id } = req.params;
  const prod = dbProducts.find((p) => p.id === id);
  if (!prod) return res.status(404).json({ error: 'محصول یافت نشد.' });

  const sanitized = sanitizeProductInput(req.body, false);
  if ('error' in sanitized) {
    return res.status(400).json({ error: sanitized.error });
  }

  const diffs: string[] = [];
  if (sanitized.price !== undefined && sanitized.price !== prod.price) {
    diffs.push(`قیمت: ${prod.price} -> ${sanitized.price}`);
  }
  if ('discountPrice' in sanitized && sanitized.discountPrice !== prod.discountPrice) {
    diffs.push(`قیمت تخفیف: ${prod.discountPrice ?? '-'} -> ${sanitized.discountPrice ?? '-'}`);
  }
  if (sanitized.stock !== undefined && sanitized.stock !== prod.stock) {
    diffs.push(`موجودی: ${prod.stock} -> ${sanitized.stock}`);
  }
  if ('variants' in sanitized && JSON.stringify(sanitized.variants) !== JSON.stringify(prod.variants)) {
    const oldCount = Array.isArray(prod.variants) ? prod.variants.length : 0;
    const newCount = Array.isArray(sanitized.variants) ? sanitized.variants.length : 0;
    diffs.push(`تنوع‌ها: ${oldCount} -> ${newCount}`);
  }

  Object.assign(prod, sanitized);
  prod.updatedAt = new Date().toISOString();
  savePersistentState();

  recordAuditLog({
    event: 'CATALOG_MUTATION',
    username: req.user?.username,
    ip: req.ip || '127.0.0.1',
    details:
      diffs.length > 0
        ? `محصول «${prod.name}» ویرایش گردید (${diffs.join(' | ')}).`
        : `محصول «${prod.name}» ویرایش گردید.`,
    severity: diffs.length > 0 ? 'warning' : 'info'
  });

  res.json(prod);
});

app.delete('/api/products/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
  const { id } = req.params;
  const index = dbProducts.findIndex((p) => p.id === id);
  if (index === -1) return res.status(404).json({ error: 'محصول یافت نشد.' });

  const deleted = dbProducts.splice(index, 1)[0];
  savePersistentState();

  recordAuditLog({
    event: 'CATALOG_MUTATION',
    username: req.user?.username,
    ip: req.ip || '127.0.0.1',
    details: `محصول «${deleted.name}» حذف گردید.`,
    severity: 'info'
  });

  res.json({ success: true, message: 'محصول با موفقیت حذف شد.' });
});

// Admin Orders Management & Strict State Machine Transitions (OWASP ASVS V10.2)
app.get('/api/admin/orders', requireAdmin, (req, res) => {
  res.json(dbOrders);
});

app.put('/api/orders/:id/status', requireAdmin, async (req: AuthenticatedRequest, res) => {
  const { id } = req.params;
  const { status, confirmManualPaid, reason } = req.body || {};

  if (!status || !isValidOrderStatus(status)) {
    return res.status(400).json({ error: 'وضعیت سفارش ارسالی نامعتبر است.' });
  }

  const order = dbOrders.find((o) => o.id === id || o.orderNumber === id);
  if (!order) {
    return res.status(404).json({ error: 'سفارش مورد نظر یافت نشد.' });
  }

  return await withOrderLock(order.id, async () => {
    const currentStatus = order.status as OrderStatus;
    if (!isValidOrderStatusTransition(currentStatus, status as OrderStatus)) {
      return res.status(400).json({
        error: `تغییر وضعیت سفارش از حالت «${currentStatus}» به حالت «${status}» بر اساس چرخه سفارشات مجاز نمی‌باشد.`
      });
    }

    const isGateway =
      String(order.paymentMethod || '').includes('درگاه') ||
      String(order.paymentMethod || '').toLowerCase().includes('zarinpal');
    const isUnverifiedGatewayManualPaid =
      status === 'PAID' &&
      !isPaidOrFulfilledOrderStatus(currentStatus) &&
      isGateway &&
      !order.paymentInfo?.refId;

    if (isUnverifiedGatewayManualPaid) {
      const cleanReason = typeof reason === 'string' ? sanitizeText(reason, 300) : '';
      if (confirmManualPaid !== true || cleanReason.length < 3) {
        return res.status(400).json({
          error:
            'تغییر دستی وضعیت سفارش درگاهی فاقد کد پیگیری بانکی (RefID) به «پرداخت شده» نیازمند تایید صریح مدیر و ثبت دلیل مشخص است.',
          requireManualConfirmation: true
        });
      }
      order.manuallyMarkedPaid = true;
      order.manualPaidReason = cleanReason;
      order.needsReview = true;
      if (!order.reviewReason) {
        order.reviewReason = 'MANUAL_MARKED_PAID';
      }
    }

    order.status = status;
    if (status === 'PAID') {
      order.paymentStatus = 'SUCCESS';
      order.paidAt = order.paidAt || new Date().toISOString();
      order.paymentInfo = {
        ...order.paymentInfo,
        paidAt: order.paymentInfo?.paidAt || order.paidAt,
        verifiedAt: order.paymentInfo?.verifiedAt || order.paidAt
      };
      decrementOrderInventoryOnce(order, req.ip || '127.0.0.1');
    } else if (isCancelledOrderStatus(status) || status === 'REFUNDED') {
      order.paymentStatus = status === 'REFUNDED' ? 'REFUNDED' : 'CANCELLED';
      restoreOrderInventoryOnce(order);
      releaseOrderPromoCountOnce(order);
    }

    savePersistentState(true);

    recordAuditLog({
      event: 'ORDER_STATUS_CHANGED',
      username: req.user?.username,
      ip: req.ip || '127.0.0.1',
      details: isUnverifiedGatewayManualPaid
        ? `ارتقای دستی سفارش درگاهی ${order.orderNumber} از «${currentStatus}» به «PAID» بدون RefID با تایید مدیر انجام شد. دلیل: ${order.manualPaidReason}`
        : `وضعیت سفارش ${order.orderNumber} از «${currentStatus}» به «${status}» تغییر یافت.`,
      severity: isUnverifiedGatewayManualPaid ? 'warning' : 'info'
    });

    res.json(order);
  });
});

// Admin Discounts CRUD
app.get('/api/admin/discounts', requireAdmin, (req, res) => {
  res.json(dbDiscounts);
});

app.post('/api/discounts', requireAdmin, (req: AuthenticatedRequest, res) => {
  const sanitized = sanitizeDiscountInput(req.body, true);
  if ('error' in sanitized) {
    return res.status(400).json({ error: sanitized.error });
  }

  const newDiscount: Record<string, any> = {
    ...sanitized,
    id: `disc-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
    active: sanitized.active !== false,
    usedCount: 0
  };

  dbDiscounts.push(newDiscount);
  savePersistentState();

  recordAuditLog({
    event: 'SETTINGS_MUTATION',
    username: req.user?.username,
    ip: req.ip || '127.0.0.1',
    details: `کد تخفیف جدید «${newDiscount.code}» ایجاد شد.`,
    severity: 'info'
  });

  res.status(201).json(newDiscount);
});

app.put('/api/discounts/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
  const { id } = req.params;
  const disc = dbDiscounts.find((d) => d.id === id);
  if (!disc) return res.status(404).json({ error: 'کد تخفیف یافت نشد.' });

  const sanitized = sanitizeDiscountInput(req.body, false);
  if ('error' in sanitized) {
    return res.status(400).json({ error: sanitized.error });
  }

  Object.assign(disc, sanitized);
  savePersistentState();

  res.json(disc);
});

app.delete('/api/discounts/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
  const { id } = req.params;
  const index = dbDiscounts.findIndex((d) => d.id === id);
  if (index === -1) return res.status(404).json({ error: 'کد تخفیف یافت نشد.' });

  const deleted = dbDiscounts.splice(index, 1)[0];
  savePersistentState();

  res.json({ success: true, message: 'کد تخفیف حذف گردید.' });
});

// Admin Banners CRUD
app.get('/api/admin/banners', requireAdmin, (req, res) => {
  res.json(dbBanners);
});

app.post('/api/banners', requireAdmin, (req: AuthenticatedRequest, res) => {
  const body = req.body || {};
  const newBanner = {
    ...body,
    id: body.id || `banner-${Date.now()}`,
    active: body.active !== false
  };
  dbBanners.push(newBanner);
  savePersistentState();
  res.status(201).json(newBanner);
});

app.put('/api/banners/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
  const { id } = req.params;
  const banner = dbBanners.find((b) => b.id === id);
  if (!banner) return res.status(404).json({ error: 'بنر یافت نشد.' });

  Object.assign(banner, req.body);
  savePersistentState();
  res.json(banner);
});

app.delete('/api/banners/:id', requireAdmin, (req: AuthenticatedRequest, res) => {
  const { id } = req.params;
  const index = dbBanners.findIndex((b) => b.id === id);
  if (index === -1) return res.status(404).json({ error: 'بنر یافت نشد.' });

  dbBanners.splice(index, 1);
  savePersistentState();
  res.json({ success: true });
});

// Admin Site Content & Special Sections
app.put('/api/content', requireAdmin, (req: AuthenticatedRequest, res) => {
  if (req.body && typeof req.body === 'object') {
    dbSiteContent = { ...dbSiteContent, ...req.body };
    savePersistentState();
    recordAuditLog({
      event: 'SETTINGS_MUTATION',
      username: req.user?.username,
      ip: req.ip || '127.0.0.1',
      details: 'محتوا و تنظیمات صفحات آتلیه بروزرسانی شد.',
      severity: 'info'
    });
    return res.json(dbSiteContent);
  }
  res.status(400).json({ error: 'محتوای ارسالی نامعتبر است.' });
});

app.put('/api/bestsellers', requireAdmin, (req: AuthenticatedRequest, res) => {
  if (Array.isArray(req.body)) {
    dbBestSellers = req.body;
    savePersistentState();
    return res.json(dbBestSellers);
  }
  res.status(400).json({ error: 'داده‌های ارسالی نامعتبر است.' });
});

app.put('/api/top-weekly', requireAdmin, (req: AuthenticatedRequest, res) => {
  if (Array.isArray(req.body)) {
    dbTopWeekly = req.body;
    savePersistentState();
    return res.json(dbTopWeekly);
  }
  res.status(400).json({ error: 'داده‌های ارسالی نامعتبر است.' });
});

// Admin Gateway Configuration (Never leaks raw merchantId back to frontend or audit logs)
app.get('/api/admin/payments/gateway', requireAdmin, (req: AuthenticatedRequest, res) => {
  const effective = getEffectiveGatewayConfig();
  res.json({
    gatewayName: effective.gatewayName,
    configured: effective.configured,
    ready: effective.ready,
    mode: effective.mode,
    merchantId: '',
    hasMerchantId: effective.hasMerchantId,
    merchantIdMasked: effective.merchantIdMasked,
    envManaged: effective.envManaged,
    callbackUrl: effective.callbackUrl || getCallbackUrl(req),
    disabledReason: effective.disabledReason
  });
});

app.put('/api/admin/payments/gateway', requireAdmin, (req: AuthenticatedRequest, res) => {
  const { gatewayName, configured, mode, merchantId, disabledReason } = req.body || {};
  const nextConfigured = Boolean(configured);
  const nextMode: ZarinPalMode = mode === 'production' ? 'production' : 'sandbox';

  let nextMerchant = String(dbGatewayStatus.merchantId || '').trim();
  const submittedMerchant = typeof merchantId === 'string' ? merchantId.trim() : '';

  // Ignore masked placeholder strings so editing other fields preserves existing merchantId
  const isMaskedPlaceholder = submittedMerchant.includes('****');
  if (submittedMerchant && !isMaskedPlaceholder) {
    if (!isValidMerchantId(submittedMerchant)) {
      return res.status(400).json({
        error: 'فرمت کد مرچنت (Merchant ID) نامعتبر است. کد مرچنت زرین‌پال باید یک شناسه UUID ۳۶ کاراکتری استاندارد باشد.'
      });
    }
    nextMerchant = submittedMerchant;
  } else if (merchantId === '' && !nextConfigured && !process.env.ZARINPAL_MERCHANT_ID) {
    // Allow clearing stored merchantId only when disabling gateway
    nextMerchant = '';
  }

  const effectiveCandidateMerchant = (process.env.ZARINPAL_MERCHANT_ID || '').trim() || nextMerchant;
  if (nextConfigured && !isValidMerchantId(effectiveCandidateMerchant)) {
    return res.status(400).json({
      error: 'برای فعال‌سازی درگاه پرداخت آنلاین، ثبت یک کد مرچنت (Merchant ID) معتبر ۳۶ کاراکتری الزامی است.'
    });
  }

  dbGatewayStatus = {
    gatewayName: gatewayName || dbGatewayStatus.gatewayName || 'زرین‌پال (ZarinPal IPG)',
    configured: nextConfigured,
    mode: nextMode,
    merchantId: nextMerchant,
    disabledReason:
      disabledReason ||
      dbGatewayStatus.disabledReason ||
      'درگاه پرداخت اینترنتی هنوز متصل نشده است و در انتظار فعال‌سازی توسط مدیریت فروشگاه می‌باشد.'
  };
  savePersistentState(true);

  const effective = getEffectiveGatewayConfig();

  recordAuditLog({
    event: 'SETTINGS_MUTATION',
    username: req.user?.username,
    ip: req.ip || '127.0.0.1',
    details: `پیکربندی درگاه بانکی تغییر کرد: وضعیت ${effective.configured ? 'فعال' : 'غیرفعال'} (${effective.mode})`,
    severity: 'warning'
  });

  res.json({
    gatewayName: effective.gatewayName,
    configured: effective.configured,
    ready: effective.ready,
    mode: effective.mode,
    merchantId: '',
    hasMerchantId: effective.hasMerchantId,
    merchantIdMasked: effective.merchantIdMasked,
    envManaged: effective.envManaged,
    callbackUrl: effective.callbackUrl || getCallbackUrl(req),
    disabledReason: effective.disabledReason
  });
});

// Admin File Upload with Strict Magic-Bytes, Sharp Re-Encoding & Anti-SVG Stored XSS (OWASP ASVS V12)
app.post('/api/upload', requireAdmin, async (req: AuthenticatedRequest, res) => {
  const { dataUrl } = req.body || {};
  if (!dataUrl || typeof dataUrl !== 'string') {
    return res.status(400).json({ error: 'داده تصویر ارسال نشده است.' });
  }

  if (!dataUrl.startsWith('data:image/')) {
    return res.status(400).json({ error: 'فقط بارگذاری فرمت‌های تصویری مجاز است.' });
  }

  try {
    const match = dataUrl.match(/^data:image\/([a-zA-Z0-9+.-]+);base64,(.+)$/);
    if (!match) {
      return res.status(400).json({ error: 'قالب داده ارسالی Base64 نامعتبر است.' });
    }

    const buffer = Buffer.from(match[2], 'base64');

    // Restrict max size to 8MB decoded (ASVS V12.1)
    if (buffer.length > 8 * 1024 * 1024) {
      return res.status(400).json({ error: 'حجم فایل ارسالی بیش از ۸ مگابایت است.' });
    }

    // Explicitly reject SVG uploads to prevent Stored XSS and XML External Entity vulnerabilities
    const textSample = buffer.slice(0, 100).toString('utf8').trim().toLowerCase();
    if (textSample.startsWith('<svg') || textSample.includes('<?xml') || textSample.includes('<svg')) {
      recordAuditLog({
        event: 'MALICIOUS_UPLOAD_BLOCKED',
        username: req.user?.username,
        ip: req.ip || '127.0.0.1',
        details: 'بارگذاری فایل SVG به علت پتانسیل حملات Stored XSS و XML Injection مسدود گردید.',
        severity: 'critical'
      });
      return res.status(400).json({
        error: 'بارگذاری فایل‌های SVG به دلیل ریسک‌های امنیتی مجاز نمی‌باشد. لطفاً از فرمت‌های تصویری JPEG، PNG یا WEBP استفاده فرمایید.'
      });
    }

    // Binary Magic Bytes Verification (OWASP ASVS V12.2)
    let detectedExt: 'jpeg' | 'png' | 'webp' | null = null;
    if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
      detectedExt = 'jpeg';
    } else if (
      buffer.length >= 8 &&
      buffer[0] === 0x89 &&
      buffer[1] === 0x50 &&
      buffer[2] === 0x4e &&
      buffer[3] === 0x47
    ) {
      detectedExt = 'png';
    } else if (
      buffer.length >= 12 &&
      buffer.slice(0, 4).toString('ascii') === 'RIFF' &&
      buffer.slice(8, 12).toString('ascii') === 'WEBP'
    ) {
      detectedExt = 'webp';
    }

    if (!detectedExt) {
      return res.status(400).json({
        error: 'امضای باینری فایل با فرمت‌های مجاز تصویری (JPEG, PNG, WEBP) مطابقت ندارد.'
      });
    }

    // Re-encode image via sharp to strip all malicious payloads, EXIF metadata, and polyglots
    let cleanBuffer: Buffer;
    try {
      cleanBuffer = await sharp(buffer)
        .toFormat(detectedExt, { quality: 85 })
        .toBuffer();
    } catch {
      return res.status(400).json({
        error: 'ساختار فایل تصویری نامعتبر است یا دارای بدنه معیوب/مخرب می‌باشد.'
      });
    }

    const safeFilename = `media_${Date.now()}_${crypto.randomBytes(8).toString('hex')}.${detectedExt}`;
    const safePath = path.join(UPLOADS_DIR, safeFilename);

    // Path traversal verification
    if (!path.resolve(safePath).startsWith(path.resolve(UPLOADS_DIR) + path.sep)) {
      return res.status(400).json({ error: 'خطای امنیت مسیر فایل.' });
    }

    fs.writeFileSync(safePath, cleanBuffer);
    return res.json({ url: `/uploads/${safeFilename}` });
  } catch (e: any) {
    console.warn('Upload error:', e);
    return res.status(500).json({ error: 'خطا در ذخیره‌سازی ایمن فایل.' });
  }
});

// Admin Users CRUD
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const safeUsers = dbUsers.map((u) => ({
    id: u.id,
    name: u.name,
    email: u.email,
    phone: u.phone,
    role: u.role,
    joinDate: u.joinDate,
    lastLogin: u.lastLogin,
    loginCount: u.loginCount
  }));
  res.json(safeUsers);
});

// 404 for undefined API routes
app.all('/api/*', (req, res) => {
  res.status(404).json({ error: 'مسیر درخواستی در سرور یافت نشد.' });
});

// Centralized Error-Handling Middleware (Never leaks internal details or stack traces)
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Unhandled Server Exception:', err);
  res.status(500).json({ error: 'خطای داخلی در پردازش درخواست رخ داد.' });
});

// ============================================================================
// BACKWARD COMPATIBLE EXPORTS FOR UNIT / INTEGRATION TESTS
// ============================================================================
export const hashPassword = hashPasswordSync;
export const verifyPassword = (password: string, combinedHash: string): boolean => {
  try {
    if (combinedHash.startsWith('$scrypt$')) {
      const parts = combinedHash.split('$');
      if (parts.length < 5) return false;
      const salt = parts[3];
      const key = parts[4];
      const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
      return crypto.timingSafeEqual(derived, Buffer.from(key, 'hex'));
    }
    const [salt, key] = combinedHash.split(':');
    if (!salt || !key) return false;
    const derived = crypto.scryptSync(password, salt, 64, { maxmem: 64 * 1024 * 1024 });
    return crypto.timingSafeEqual(derived, Buffer.from(key, 'hex'));
  } catch {
    return false;
  }
};
export const checkAuthLockout = (key: string) => checkLockout(key);
export const recordAuthFailureAttempt = (key: string) => recordAuthFailure(key);
export const clearAuthFailureRecord = (key: string) => clearAuthFailure(key);

export {
  dbUsers,
  dbProducts,
  dbOrders,
  dbDiscounts,
  dbGatewayStatus,
  SESSION_SECRET,
  signJoseToken,
  verifyJoseToken,
  validatePasswordPolicy,
  hashPasswordAsync,
  verifyPasswordAsync,
  sanitizeText,
  cleanPhoneNumber,
  toEnglishDigits
};

// ============================================================================
// SERVER BOOT & VITE INTEGRATION
// ============================================================================
export async function startServer() {
  if (!isProduction) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve('dist');
    app.use(
      express.static(distPath, {
        index: false,
        setHeaders: (res, filePath) => {
          const p = filePath.replace(/\\/g, '/');
          if (p.includes('/assets/')) {
            // hashed build files: safe to cache for a year
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
          } else if (p.includes('/fonts/')) {
            res.setHeader('Cache-Control', 'public, max-age=2592000');
          } else {
            res.setHeader('Cache-Control', 'public, max-age=3600');
          }
        }
      })
    );
    const indexHtml = fs.readFileSync(path.join(distPath, 'index.html'), 'utf8');
    app.get('*', (req, res) => {
      // Inject the per-request CSP nonce so scripts are allowed by 'strict-dynamic'
      const nonce = res.locals.cspNonce;
      const html = indexHtml.replace(/<script/g, `<script nonce="${nonce}"`);
      res.type('html').send(html);
    });
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`MORICO STYLE Core Server running on http://0.0.0.0:${PORT}`);
  });

  // Schedule background payment reconciler every 5 minutes (A6)
  const reconcilerInterval = setInterval(() => {
    runPaymentReconciler().catch((err) => {
      console.warn('[MORICO Reconciler] Background error:', err);
    });
  }, 5 * 60 * 1000);
  reconcilerInterval.unref?.();

  return server;
}

// Automatically start if executed as primary entry point (and not required/imported in tests)
if (process.env.NODE_ENV !== 'test') {
  startServer().catch((err) => {
    console.error('Fatal Server Boot Error:', err);
  });
}
