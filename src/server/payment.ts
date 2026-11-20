export type ZarinPalMode = 'sandbox' | 'production';

export interface ZarinPalRequestInput {
  merchantId: string;
  amountToman: number;
  description: string;
  callbackUrl: string;
  mode?: ZarinPalMode;
  mobile?: string;
  email?: string;
  orderId?: string;
  timeoutMs?: number;
}

export interface ZarinPalRequestResult {
  success: boolean;
  code: number;
  authority?: string;
  paymentUrl?: string;
  feeType?: string;
  fee?: number;
  amountToman: number;
  amountRials: number;
  currency: 'IRR';
  mode: ZarinPalMode;
  message: string;
  networkError?: boolean;
  timeout?: boolean;
}

export interface ZarinPalVerifyInput {
  authority: string;
  amountToman: number;
  merchantId: string;
  mode?: ZarinPalMode;
  timeoutMs?: number;
}

export interface ZarinPalVerifyResult {
  success: boolean;
  code: number;
  message: string;
  refId?: string;
  cardPan?: string;
  cardHash?: string;
  feeType?: string;
  fee?: number;
  alreadyVerified?: boolean;
  ambiguous?: boolean;
  networkError?: boolean;
  timeout?: boolean;
}

export interface ZarinPalTransportRequest {
  url: string;
  body: Record<string, any>;
  timeoutMs: number;
}

export interface ZarinPalTransportResponse {
  ok: boolean;
  status: number;
  json?: any;
}

export type ZarinPalTransport = (
  req: ZarinPalTransportRequest
) => Promise<ZarinPalTransportResponse>;

const UUID_MERCHANT_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const ZARINPAL_MIN_TOMAN = 1000; // ZarinPal minimum transaction is 10,000 Rials (1,000 Tomans)
const DEFAULT_ZARINPAL_TIMEOUT_MS = 12000;

let testOnlyTransport: ZarinPalTransport | null = null;

/**
 * Registers an isolated transport stub ONLY when NODE_ENV === 'test'.
 * Never usable in development or production builds.
 */
export function setZarinPalTestTransport(transport: ZarinPalTransport | null): void {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('setZarinPalTestTransport is strictly restricted to NODE_ENV=test');
  }
  testOnlyTransport = transport;
}

export function isValidMerchantId(merchantId?: string | null): boolean {
  if (!merchantId || typeof merchantId !== 'string') return false;
  return UUID_MERCHANT_REGEX.test(merchantId.trim());
}

export function maskMerchantId(merchantId?: string | null): string {
  if (!merchantId || typeof merchantId !== 'string') return '';
  const clean = merchantId.trim();
  if (clean.length < 12) return '';
  return `${clean.slice(0, 8)}-****-****-****-${clean.slice(-12)}`;
}

/**
 * Converts Tomans (storefront unit) to Rials (ZarinPal IRR unit) ONCE.
 */
export function tomanToRial(amountToman: number): number {
  const numeric = Number(amountToman);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return 0;
  }
  return Math.round(numeric) * 10;
}

export function getZarinPalEndpoints(mode: ZarinPalMode = 'sandbox') {
  const isProd = mode === 'production';
  const baseHost = isProd ? 'https://payment.zarinpal.com' : 'https://sandbox.zarinpal.com';
  return {
    mode: isProd ? ('production' as const) : ('sandbox' as const),
    requestUrl: `${baseHost}/pg/v4/payment/request.json`,
    verifyUrl: `${baseHost}/pg/v4/payment/verify.json`,
    startPayBase: `${baseHost}/pg/StartPay/`
  };
}

export function mapZarinPalErrorCode(code: number, fallbackMessage?: string): string {
  const messages: Record<number, string> = {
    [-9]: 'خطای اعتبارسنجی اطلاعات ارسالی به درگاه زرین‌پال (کد -۹).',
    [-10]: 'کد مرچنت یا IP پذیرنده در زرین‌پال نامعتبر است (کد -۱۰).',
    [-11]: 'کد مرچنت زرین‌پال فعال نیست یا درگاه تایید نشده است (کد -۱۱).',
    [-12]: 'تعداد تلاش‌های ارسال درخواست بیش از حد مجاز بوده است (کد -۱۲).',
    [-13]: 'سقف تراکنش پذیرنده یا ترمینال بانکی رعایت نشده است (کد -۱۳).',
    [-14]: 'دامنه آدرس بازگشت (Callback URL) با دامنه ثبت‌شده در زرین‌پال مغایرت دارد (کد -۱۴).',
    [-15]: 'ترمینال پذیرنده درگاه زرین‌پال در حال حاضر معلق است (کد -۱۵).',
    [-16]: 'سطح پذیرنده زرین‌پال برای این نوع تراکنش مجاز نیست (کد -۱۶).',
    [-30]: 'پذیرنده اجازه دسترسی به سرویس تسویه اشتراکی ندارد (کد -۳۰).',
    [-40]: 'پارامترهای اضافی یا نامعتبر به درگاه زرین‌پال ارسال شده است (کد -۴۰).',
    [-41]: 'حداکثر مبلغ مجاز تراکنش در درگاه زرین‌پال رعایت نشده است (کد -۴۱).',
    [-50]: 'مبلغ پرداختی با مبلغ تراکنش در زرین‌پال مطابقت ندارد (کد -۵۰).',
    [-51]: 'پرداخت ناموفق بوده یا توسط کاربر لغو شده است (کد -۵۱).',
    [-52]: 'خطای غیرمنتظره در درگاه پرداخت زرین‌پال رخ داده است (کد -۵۲).',
    [-53]: 'تراکنش متعلق به این کد مرچنت نمی‌باشد (کد -۵۳).',
    [-54]: 'شناسه مرجع تراکنش (Authority) نامعتبر است (کد -۵۴).',
    [-55]: 'تراکنش مورد نظر در سامانه زرین‌پال یافت نشد (کد -۵۵).'
  };
  return messages[code] || fallbackMessage || `خطای درگاه زرین‌پال (کد ${code}).`;
}

async function postZarinPalJson(
  url: string,
  body: Record<string, any>,
  timeoutMs = DEFAULT_ZARINPAL_TIMEOUT_MS
): Promise<{
  ok: boolean;
  status: number;
  json?: any;
  networkError?: boolean;
  timeout?: boolean;
  errorMessage?: string;
}> {
  if (process.env.NODE_ENV === 'test' && testOnlyTransport) {
    try {
      const res = await testOnlyTransport({ url, body, timeoutMs });
      return { ok: res.ok, status: res.status, json: res.json };
    } catch (err: any) {
      const isTimeout = err?.name === 'AbortError' || String(err?.message || '').toLowerCase().includes('timeout');
      return {
        ok: false,
        status: 0,
        networkError: true,
        timeout: isTimeout,
        errorMessage: err?.message || 'خطا در ارتباط شبکه با درگاه زرین‌پال.'
      };
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json'
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });

    let parsed: any = undefined;
    try {
      parsed = await response.json();
    } catch {
      parsed = undefined;
    }

    return {
      ok: response.ok,
      status: response.status,
      json: parsed
    };
  } catch (err: any) {
    const isTimeout = err?.name === 'AbortError';
    return {
      ok: false,
      status: 0,
      networkError: true,
      timeout: isTimeout,
      errorMessage: isTimeout
        ? 'زمان پاسخ‌گویی درگاه پرداخت زرین‌پال به پایان رسید.'
        : err?.message || 'خطای شبکه در ارتباط با سرور زرین‌پال.'
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Initiates a real ZarinPal v4 Payment Request (/pg/v4/payment/request.json).
 */
export async function requestZarinPalPayment(
  input: ZarinPalRequestInput
): Promise<ZarinPalRequestResult> {
  const mode: ZarinPalMode = input.mode === 'production' ? 'production' : 'sandbox';
  const endpoints = getZarinPalEndpoints(mode);
  const cleanMerchant = String(input.merchantId || '').trim();
  const amountToman = Math.round(Number(input.amountToman));
  const amountRials = tomanToRial(amountToman);

  if (!isValidMerchantId(cleanMerchant)) {
    return {
      success: false,
      code: -10,
      amountToman,
      amountRials,
      currency: 'IRR',
      mode,
      message: 'کد مرچنت (Merchant ID) درگاه زرین‌پال تنظیم نشده یا قالب UUID ۳۶ کاراکتری ندارد.'
    };
  }

  if (!Number.isFinite(amountToman) || amountToman < ZARINPAL_MIN_TOMAN || amountRials < 10000) {
    return {
      success: false,
      code: -9,
      amountToman: Number.isFinite(amountToman) ? amountToman : 0,
      amountRials,
      currency: 'IRR',
      mode,
      message: 'مبلغ سفارش برای ارسال به درگاه زرین‌پال باید حداقل ۱,۰۰۰ تومان (۱۰,۰۰۰ ریال) باشد.'
    };
  }

  if (!input.callbackUrl || !/^https?:\/\//i.test(input.callbackUrl)) {
    return {
      success: false,
      code: -14,
      amountToman,
      amountRials,
      currency: 'IRR',
      mode,
      message: 'آدرس بازگشت درگاه پرداخت (Callback URL) نامعتبر است.'
    };
  }

  const metadata: Record<string, string> = {};
  if (input.mobile) metadata.mobile = String(input.mobile).trim();
  if (input.email) metadata.email = String(input.email).trim();
  if (input.orderId) metadata.order_id = String(input.orderId).trim();

  const payload: Record<string, any> = {
    merchant_id: cleanMerchant,
    amount: amountRials,
    currency: 'IRR',
    description: String(input.description || 'خرید از فروشگاه MORICO STYLE').slice(0, 255),
    callback_url: input.callbackUrl
  };
  if (Object.keys(metadata).length > 0) {
    payload.metadata = metadata;
  }

  const httpRes = await postZarinPalJson(
    endpoints.requestUrl,
    payload,
    input.timeoutMs ?? DEFAULT_ZARINPAL_TIMEOUT_MS
  );

  if (httpRes.networkError) {
    return {
      success: false,
      code: httpRes.timeout ? -504 : -500,
      amountToman,
      amountRials,
      currency: 'IRR',
      mode,
      networkError: true,
      timeout: httpRes.timeout,
      message: httpRes.errorMessage || 'خطا در اتصال به سرور درگاه زرین‌پال.'
    };
  }

  const body = httpRes.json || {};
  const data = body.data;
  const errObj = Array.isArray(body.errors) ? body.errors[0] : body.errors;

  if (httpRes.ok && data && Number(data.code) === 100 && typeof data.authority === 'string' && data.authority.trim()) {
    const authority = data.authority.trim();
    return {
      success: true,
      code: 100,
      authority,
      paymentUrl: `${endpoints.startPayBase}${encodeURIComponent(authority)}`,
      feeType: data.fee_type,
      fee: typeof data.fee === 'number' ? data.fee : undefined,
      amountToman,
      amountRials,
      currency: 'IRR',
      mode,
      message: 'درخواست پرداخت در درگاه زرین‌پال با موفقیت ثبت شد.'
    };
  }

  const errCode = Number(errObj?.code ?? data?.code ?? (httpRes.status ? -httpRes.status : -502));
  return {
    success: false,
    code: errCode,
    amountToman,
    amountRials,
    currency: 'IRR',
    mode,
    message: mapZarinPalErrorCode(errCode, errObj?.message || data?.message)
  };
}

/**
 * Verifies a ZarinPal v4 Payment (/pg/v4/payment/verify.json).
 * Never synthesizes fake RefIDs or marks payments successful without a valid code 100 or 101 response.
 */
export async function verifyZarinPalTransaction(
  authorityOrInput: string | ZarinPalVerifyInput,
  amountTomanArg?: number,
  merchantIdArg?: string,
  isSandboxOrModeArg?: boolean | ZarinPalMode
): Promise<ZarinPalVerifyResult> {
  const input: ZarinPalVerifyInput =
    typeof authorityOrInput === 'object'
      ? authorityOrInput
      : {
          authority: authorityOrInput,
          amountToman: Number(amountTomanArg || 0),
          merchantId: String(merchantIdArg || ''),
          mode:
            typeof isSandboxOrModeArg === 'string'
              ? isSandboxOrModeArg
              : isSandboxOrModeArg === false
              ? 'production'
              : 'sandbox'
        };

  const authority = typeof input.authority === 'string' ? input.authority.trim() : '';
  const mode: ZarinPalMode = input.mode === 'production' ? 'production' : 'sandbox';
  const endpoints = getZarinPalEndpoints(mode);
  const cleanMerchant = String(input.merchantId || '').trim();
  const amountRials = tomanToRial(input.amountToman);

  if (!authority || authority.length < 8) {
    return {
      success: false,
      code: -54,
      message: 'شناسه مرجع تراکنش (Authority) نامعتبر است.'
    };
  }

  if (!isValidMerchantId(cleanMerchant)) {
    return {
      success: false,
      code: -10,
      message: 'پیکربندی کد مرچنت درگاه زرین‌پال نامعتبر یا تکمیل نشده است.'
    };
  }

  if (!Number.isFinite(input.amountToman) || amountRials < 10000) {
    return {
      success: false,
      code: -9,
      message: 'مبلغ سفارش برای راستی‌آزمایی تراکنش نامعتبر است.'
    };
  }

  const httpRes = await postZarinPalJson(
    endpoints.verifyUrl,
    {
      merchant_id: cleanMerchant,
      amount: amountRials,
      authority
    },
    input.timeoutMs ?? DEFAULT_ZARINPAL_TIMEOUT_MS
  );

  // Network/Timeout/5xx non-JSON errors must be treated as AMBIGUOUS so orders are not wrongly discarded or marked PAID
  if (httpRes.networkError || (!httpRes.ok && httpRes.status >= 500 && !httpRes.json)) {
    return {
      success: false,
      code: httpRes.timeout ? -504 : -500,
      ambiguous: true,
      networkError: true,
      timeout: httpRes.timeout,
      message:
        httpRes.errorMessage ||
        'ارتباط با سرور زرین‌پال برای تایید تراکنش برقرار نشد. وضعیت تراکنش در حالت بررسی مجدد (Pending Verify) قرار گرفت.'
    };
  }

  const body = httpRes.json || {};
  const data = body.data;
  const errObj = Array.isArray(body.errors) ? body.errors[0] : body.errors;
  const code = Number(data?.code ?? errObj?.code ?? -52);

  if (httpRes.ok && data && (code === 100 || code === 101)) {
    const refIdRaw = data.ref_id ?? data.refId;
    if (refIdRaw === undefined || refIdRaw === null || String(refIdRaw).trim() === '') {
      return {
        success: false,
        code: -52,
        ambiguous: true,
        message: 'پاسخ تایید درگاه زرین‌پال فاقد شناسه پیگیری بانکی (ref_id) معتبر بود.'
      };
    }
    return {
      success: true,
      code,
      alreadyVerified: code === 101,
      message:
        code === 101
          ? 'تراکنش قبلاً با موفقیت تایید شده است (تکراری / Idempotent).'
          : 'تراکنش با موفقیت در درگاه زرین‌پال تایید گردید.',
      refId: String(refIdRaw),
      cardPan: typeof data.card_pan === 'string' ? data.card_pan : undefined,
      cardHash: typeof data.card_hash === 'string' ? data.card_hash : undefined,
      feeType: typeof data.fee_type === 'string' ? data.fee_type : undefined,
      fee: typeof data.fee === 'number' ? data.fee : undefined
    };
  }

  return {
    success: false,
    code,
    message: mapZarinPalErrorCode(code, errObj?.message || data?.message)
  };
}
