/**
 * Automated End-to-End ZarinPal IPG & Financial Security Test Suite
 * Covers all 16 mandatory payment, inventory, currency, state-machine, idempotency,
 * concurrency, timeout recovery, and security test scenarios using supertest.
 */

process.env.NODE_ENV = 'test';

import fs from 'fs';
import path from 'path';
import request from 'supertest';
import {
  app,
  dbProducts,
  dbOrders,
  dbUsers,
  dbDiscounts,
  runPaymentReconciler,
  signJoseToken,
  SESSION_SECRET
} from '../server';
import { DATA_FILE, DESIGN_UPLOADS_DIR, getRecentAuditLogs } from '../src/server/storage';
import {
  setZarinPalTestTransport,
  tomanToRial,
  verifyZarinPalTransaction,
  type ZarinPalTransportRequest
} from '../src/server/payment';

let orderIpCounter = 1;
function nextOrderIp(): string {
  const third = Math.floor(orderIpCounter / 200) + 1;
  const fourth = (orderIpCounter % 200) + 1;
  orderIpCounter++;
  return `10.22.${third}.${fourth}`;
}

interface PaymentTestResult {
  id: number;
  name: string;
  passed: boolean;
  details: string;
}

const results: PaymentTestResult[] = [];

function record(id: number, name: string, passed: boolean, details: string) {
  results.push({ id, name, passed, details });
  console.log(`${passed ? '✅' : '❌'} [تست ${id}] ${name}: ${details}`);
}

const TEST_MERCHANT_UUID = '11111111-2222-4333-8444-555555555555';

async function configureGateway(
  adminToken: string,
  config: {
    configured: boolean;
    mode?: 'sandbox' | 'production';
    merchantId?: string;
    disabledReason?: string;
  }
) {
  const res = await request(app)
    .put('/api/admin/payments/gateway')
    .set('Authorization', `Bearer ${adminToken}`)
    .send({
      gatewayName: 'زرین‌پال (ZarinPal IPG)',
      configured: config.configured,
      mode: config.mode || 'sandbox',
      ...(config.merchantId !== undefined ? { merchantId: config.merchantId } : {}),
      disabledReason:
        config.disabledReason ||
        'درگاه پرداخت اینترنتی هنوز متصل نشده است و در انتظار فعال‌سازی توسط مدیریت فروشگاه می‌باشد.'
    });
  return res;
}

async function runPaymentTestSuite() {
  console.log('========================================================================');
  console.log('آغاز اجرای ۱۶ تست جامع پرداخت زرین‌پال، موجودی، واحد پول و امنیت');
  console.log('========================================================================\n');

  const hadDataFile = fs.existsSync(DATA_FILE);
  const originalDataSnapshot = hadDataFile ? fs.readFileSync(DATA_FILE, 'utf8') : null;

  // Snapshot initial in-memory gateway status via admin API or restore cleanly at the end
  const adminUser = dbUsers.find((u) => u.role === 'admin') || dbUsers[0];
  if (adminUser) {
    adminUser.mustChangePassword = false;
  }
  const adminToken = await signJoseToken(adminUser, SESSION_SECRET!);

  const prodRegular = {
    id: 'prod-pay-test-regular',
    name: 'هودی باکس‌فیت تستی پرداخت',
    price: 900000,
    stock: 10,
    status: 'published',
    allowCustomization: true,
    customizable: true
  };
  const prodZeroStock = {
    id: 'prod-pay-test-zero',
    name: 'تیشرت ناموجود تستی پرداخت',
    price: 400000,
    stock: 0,
    status: 'published',
    allowCustomization: false
  };
  dbProducts.push(prodRegular, prodZeroStock);

  const testDiscount = {
    code: 'PAYTEST10',
    type: 'percentage',
    percent: 10,
    active: true,
    usedCount: 0,
    maxUses: 100
  };
  dbDiscounts.push(testDiscount);

  let createdOrderIds: string[] = [];

  try {
    // ------------------------------------------------------------------------
    // تست ۱: درگاه غیرفعال
    // - درگاه غیرفعال باشد
    // - پرداخت آنلاین مسدود باشد (۴۰۰) و Paid نشود
    // - روش کارت‌به‌کارت همچنان PENDING_PAYMENT کار کند (بدون RefID ساختگی و کسر موجودی)
    // ------------------------------------------------------------------------
    try {
      await configureGateway(adminToken, {
        configured: false,
        mode: 'sandbox',
        merchantId: ''
      });

      const statusRes = await request(app).get('/api/payments/status');
      const blockedGatewayRes = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری درگاه غیرفعال',
          customerPhone: '09121112233',
          customerAddress: 'تهران، خیابان فرشته، پلاک ۱',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911111',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });

      const cardOrderRes = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری کارت به کارت',
          customerPhone: '09121112233',
          customerAddress: 'تهران، خیابان فرشته، پلاک ۱',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911111',
          paymentMethod: 'card',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      if (cardOrderRes.body?.id) createdOrderIds.push(cardOrderRes.body.id);

      const passed1 =
        statusRes.status === 200 &&
        statusRes.body?.ready === false &&
        statusRes.body?.merchantId === undefined &&
        blockedGatewayRes.status === 400 &&
        cardOrderRes.status === 201 &&
        cardOrderRes.body?.status === 'PENDING_PAYMENT' &&
        !cardOrderRes.body?.paymentInfo?.refId &&
        prodRegular.stock === 10;

      record(
        1,
        'درگاه غیرفعال و سلامت کارت‌به‌کارت',
        passed1,
        `ready=${statusRes.body?.ready}, gatewayStatus=${blockedGatewayRes.status}, cardStatus=${cardOrderRes.status}/${cardOrderRes.body?.status}, stock=${prodRegular.stock}`
      );
    } catch (e: any) {
      record(1, 'درگاه غیرفعال و سلامت کارت‌به‌کارت', false, e.message);
    }

    // Enable gateway in sandbox mode with valid UUID for remaining tests
    const gwEnableRes = await configureGateway(adminToken, {
      configured: true,
      mode: 'sandbox',
      merchantId: TEST_MERCHANT_UUID
    });
    if (gwEnableRes.status !== 200 || !gwEnableRes.body?.ready || gwEnableRes.body?.merchantId !== '') {
      throw new Error(`Failed to configure gateway cleanly: ${JSON.stringify(gwEnableRes.body)}`);
    }

    // ------------------------------------------------------------------------
    // تست ۲: Request ناموفق زرین‌پال
    // - API زرین‌پال خطا دهد -> سفارش Paid نشود، RefID ثبت نشود، خطای ۵۰۲ مناسب
    // ------------------------------------------------------------------------
    try {
      setZarinPalTestTransport(async () => ({
        ok: false,
        status: 400,
        json: { errors: { code: -11, message: 'Merchant is not active' } }
      }));

      const orderRes = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری تست ۲',
          customerPhone: '09122223344',
          customerAddress: 'تهران، جردن، کوچه ۲',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911112',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      createdOrderIds.push(orderRes.body.id);

      const payReqRes = await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', orderRes.body.paymentToken)
        .send({ orderNumber: orderRes.body.orderNumber });

      const stored = dbOrders.find((o) => o.id === orderRes.body.id);
      const passed2 =
        orderRes.status === 201 &&
        payReqRes.status === 502 &&
        typeof payReqRes.body?.error === 'string' &&
        stored?.status === 'PENDING_PAYMENT' &&
        stored?.paymentStatus === 'FAILED' &&
        !stored?.paymentInfo?.refId &&
        prodRegular.stock === 10;

      record(
        2,
        'Request ناموفق زرین‌پال',
        passed2,
        `http=${payReqRes.status}, orderStatus=${stored?.status}, paymentStatus=${stored?.paymentStatus}`
      );
    } catch (e: any) {
      record(2, 'Request ناموفق زرین‌پال', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۳: Request موفق + تبدیل واحد تومان به ریال
    // - مقدار ارسالی به زرین‌پال دقیقاً تومان * ۱۰ با currency: IRR
    // - Authority واقعی دریافت شود و PaymentAttempt و paymentUrl معتبر ثبت شوند
    // ------------------------------------------------------------------------
    let capturedRequestPayload: ZarinPalTransportRequest | null = null;
    let test3Order: any = null;
    const auth3 = 'S00000000000000000000000000000003333';
    try {
      setZarinPalTestTransport(async (req) => {
        capturedRequestPayload = req;
        return {
          ok: true,
          status: 200,
          json: { data: { code: 100, authority: auth3, fee_type: 'Merchant', fee: 5000 } }
        };
      });

      const orderRes = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری تست ۳',
          customerPhone: '09123334455',
          customerAddress: 'تهران، سعادت‌آباد، بلوار دریا، پلاک ۳',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911113',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }], // 900,000 + 45,000 = 945,000 Toman
          total: 945000
        });
      test3Order = orderRes.body;
      createdOrderIds.push(test3Order.id);

      const payReqRes = await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', test3Order.paymentToken)
        .send({ orderNumber: test3Order.orderNumber, idempotencyKey: 'idem-req-test-3' });

      const stored = dbOrders.find((o) => o.id === test3Order.id);
      const expectedRials = tomanToRial(945000); // 9,450,000 IRR
      const passed3 =
        payReqRes.status === 200 &&
        payReqRes.body?.authority === auth3 &&
        payReqRes.body?.paymentUrl === `https://sandbox.zarinpal.com/pg/StartPay/${auth3}` &&
        capturedRequestPayload?.url === 'https://sandbox.zarinpal.com/pg/v4/payment/request.json' &&
        capturedRequestPayload?.body?.amount === expectedRials &&
        capturedRequestPayload?.body?.currency === 'IRR' &&
        Array.isArray(stored?.paymentAttempts) &&
        stored.paymentAttempts.length === 1 &&
        stored.paymentAttempts[0].status === 'PENDING' &&
        stored.paymentAttempts[0].amountRials === expectedRials;

      record(
        3,
        'Request موفق و تبدیل واحد تومان به ریال',
        passed3,
        `authority=${payReqRes.body?.authority}, amountIRR=${capturedRequestPayload?.body?.amount}, attempts=${stored?.paymentAttempts?.length}`
      );
    } catch (e: any) {
      record(3, 'Request موفق و تبدیل واحد تومان به ریال', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۴: پرداخت موفق از طریق Callback -> Verify -> RefID -> کسر موجودی یک‌بار
    // ------------------------------------------------------------------------
    let verifyCallsTest4 = 0;
    let capturedVerifyAmount4 = 0;
    try {
      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/verify.json')) {
          verifyCallsTest4++;
          capturedVerifyAmount4 = req.body.amount;
          return {
            ok: true,
            status: 200,
            json: {
              data: {
                code: 100,
                ref_id: 987654321,
                card_pan: '6037-99**-****-1234',
                card_hash: 'HASH_REAL_TEST_4',
                fee_type: 'Merchant',
                fee: 5000
              }
            }
          };
        }
        throw new Error('Unexpected endpoint');
      });

      const cbRes = await request(app).get(
        `/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth3)}&Status=OK`
      );

      const stored = dbOrders.find((o) => o.id === test3Order.id);
      const passed4 =
        cbRes.status === 302 &&
        cbRes.headers.location === `/?payment=success&orderNumber=${test3Order.orderNumber}` &&
        verifyCallsTest4 === 1 &&
        capturedVerifyAmount4 === 9450000 &&
        stored?.status === 'PAID' &&
        stored?.paymentStatus === 'SUCCESS' &&
        stored?.paymentInfo?.refId === '987654321' &&
        stored?.paymentInfo?.cardPanMask === '6037-99**-****-1234' &&
        stored?.inventoryDeducted === true &&
        prodRegular.stock === 9;

      record(
        4,
        'Callback موفق -> Verify واقعی -> ثبت RefID و کسر موجودی یک‌بار',
        passed4,
        `redirect=${cbRes.headers.location}, refId=${stored?.paymentInfo?.refId}, stock=${prodRegular.stock}`
      );
    } catch (e: any) {
      record(4, 'Callback موفق -> Verify واقعی', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۷: Callback تکراری روی همان سفارش Paid
    // - نباید Verify یا کسر موجودی مجدد انجام شود
    // ------------------------------------------------------------------------
    try {
      let extraVerifyCalls = 0;
      setZarinPalTestTransport(async () => {
        extraVerifyCalls++;
        return { ok: true, status: 200, json: { data: { code: 101, ref_id: 987654321 } } };
      });

      const dupCb = await request(app).get(
        `/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth3)}&Status=OK`
      );
      const passed7 =
        dupCb.status === 302 &&
        dupCb.headers.location === `/?payment=success&orderNumber=${test3Order.orderNumber}` &&
        extraVerifyCalls === 0 &&
        prodRegular.stock === 9;

      record(
        7,
        'Callback تکراری (Idempotent)',
        passed7,
        `redirect=${dupCb.headers.location}, extraVerifyCalls=${extraVerifyCalls}, stock=${prodRegular.stock}`
      );
    } catch (e: any) {
      record(7, 'Callback تکراری', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۸: Verify تکراری روی سفارش Paid (POST /api/payments/zarinpal/verify)
    // - پاسخ امن idempotent code 101، وضعیت و موجودی خراب نشود
    // ------------------------------------------------------------------------
    try {
      const dupVerify = await request(app)
        .post('/api/payments/zarinpal/verify')
        .set('X-Payment-Token', test3Order.paymentToken)
        .send({ authority: auth3, orderNumber: test3Order.orderNumber });

      const stored = dbOrders.find((o) => o.id === test3Order.id);
      const passed8 =
        dupVerify.status === 200 &&
        dupVerify.body?.success === true &&
        dupVerify.body?.code === 101 &&
        dupVerify.body?.refId === '987654321' &&
        stored?.status === 'PAID' &&
        prodRegular.stock === 9;

      record(
        8,
        'Verify تکراری (Idempotent code 101)',
        passed8,
        `http=${dupVerify.status}, code=${dupVerify.body?.code}, stock=${prodRegular.stock}`
      );
    } catch (e: any) {
      record(8, 'Verify تکراری', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۱۶: پرداخت تکراری برای یک سفارش Paid
    // - درخواست جدید request.json روی سفارش Paid با ۴۰۹ رد شود
    // ------------------------------------------------------------------------
    try {
      const repayRes = await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', test3Order.paymentToken)
        .send({ orderNumber: test3Order.orderNumber });

      const passed16 = repayRes.status === 409 && typeof repayRes.body?.error === 'string';
      record(
        16,
        'جلوگیری از پرداخت تکراری سفارش Paid',
        passed16,
        `http=${repayRes.status}, error=${repayRes.body?.error}`
      );
    } catch (e: any) {
      record(16, 'جلوگیری از پرداخت تکراری سفارش Paid', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۵: پرداخت ناموفق در Verify (کد -51)
    // - سفارش Paid نشود، RefID ثبت نشود، موجودی کاهش نیابد
    // ------------------------------------------------------------------------
    try {
      const auth5 = 'S00000000000000000000000000000005555';
      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/request.json')) {
          return { ok: true, status: 200, json: { data: { code: 100, authority: auth5 } } };
        }
        return {
          ok: true,
          status: 200,
          json: { errors: { code: -51, message: 'Payment failed or cancelled' } }
        };
      });

      const order5 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری تست ۵',
          customerPhone: '09125556677',
          customerAddress: 'تهران، پاسداران، بوستان ۵',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911115',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      createdOrderIds.push(order5.body.id);

      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order5.body.paymentToken)
        .send({ orderNumber: order5.body.orderNumber });

      const cb5 = await request(app).get(
        `/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth5)}&Status=OK`
      );
      const stored5 = dbOrders.find((o) => o.id === order5.body.id);

      const passed5 =
        cb5.status === 302 &&
        cb5.headers.location ===
          `/?payment=failed&reason=verification_failed&orderNumber=${order5.body.orderNumber}` &&
        stored5?.status === 'PAYMENT_FAILED' &&
        stored5?.paymentStatus === 'FAILED' &&
        !stored5?.paymentInfo?.refId &&
        prodRegular.stock === 9;

      record(
        5,
        'پرداخت ناموفق در Verify',
        passed5,
        `redirect=${cb5.headers.location}, orderStatus=${stored5?.status}, stock=${prodRegular.stock}`
      );
    } catch (e: any) {
      record(5, 'پرداخت ناموفق در Verify', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۶: لغو پرداخت توسط کاربر (Status=NOK) + Retry امن
    // ------------------------------------------------------------------------
    try {
      const auth6a = 'S00000000000000000000000000000006661';
      const auth6b = 'S00000000000000000000000000000006662';
      let reqCounter6 = 0;

      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/request.json')) {
          reqCounter6++;
          return {
            ok: true,
            status: 200,
            json: { data: { code: 100, authority: reqCounter6 === 1 ? auth6a : auth6b } }
          };
        }
        return {
          ok: true,
          status: 200,
          json: { data: { code: 100, ref_id: 666222, card_pan: '6219-86**-****-9988' } }
        };
      });

      const order6 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری تست ۶',
          customerPhone: '09126667788',
          customerAddress: 'تهران، ونک، پلاک ۶',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911116',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      createdOrderIds.push(order6.body.id);

      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order6.body.paymentToken)
        .send({ orderNumber: order6.body.orderNumber });

      const cbCancel = await request(app).get(
        `/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth6a)}&Status=NOK`
      );
      const statusRightAfterCancel = dbOrders.find((o) => o.id === order6.body.id)?.paymentStatus;

      // Safe Retry
      const retryReq = await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order6.body.paymentToken)
        .send({ orderNumber: order6.body.orderNumber });

      const cbRetryOk = await request(app).get(
        `/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth6b)}&Status=OK`
      );
      const afterRetry = dbOrders.find((o) => o.id === order6.body.id);

      const passed6 =
        cbCancel.status === 302 &&
        cbCancel.headers.location === `/?payment=cancelled&orderNumber=${order6.body.orderNumber}` &&
        statusRightAfterCancel === 'CANCELLED' &&
        retryReq.status === 200 &&
        retryReq.body?.authority === auth6b &&
        cbRetryOk.headers.location === `/?payment=success&orderNumber=${order6.body.orderNumber}` &&
        afterRetry?.status === 'PAID' &&
        afterRetry?.paymentInfo?.refId === '666222' &&
        prodRegular.stock === 8;

      record(
        6,
        'لغو پرداخت (NOK) و Retry امن',
        passed6,
        `cancel=${cbCancel.headers.location}, retryAuth=${retryReq.body?.authority}, final=${afterRetry?.status}, stock=${prodRegular.stock}`
      );
    } catch (e: any) {
      record(6, 'لغو پرداخت و Retry امن', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۹: Authority جعلی
    // ------------------------------------------------------------------------
    try {
      const auth9 = 'S00000000000000000000000000000009991';
      setZarinPalTestTransport(async () => ({
        ok: true,
        status: 200,
        json: { data: { code: 100, authority: auth9 } }
      }));

      const order9 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری تست ۹',
          customerPhone: '09129990011',
          customerAddress: 'تهران، زعفرانیه، پلاک ۹',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911119',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      createdOrderIds.push(order9.body.id);

      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order9.body.paymentToken)
        .send({ orderNumber: order9.body.orderNumber });

      const fakeVerify = await request(app)
        .post('/api/payments/zarinpal/verify')
        .set('X-Payment-Token', order9.body.paymentToken)
        .send({ authority: 'A000000000000000000000000000000FAKE', orderNumber: order9.body.orderNumber });

      const fakeCallback = await request(app).get(
        '/api/payments/zarinpal/callback?Authority=A000000000000000000000000000000FAKE&Status=OK'
      );

      const stored9 = dbOrders.find((o) => o.id === order9.body.id);
      const passed9 =
        fakeVerify.status === 400 &&
        fakeCallback.status === 302 &&
        fakeCallback.headers.location === '/?payment=failed&reason=order_not_found' &&
        stored9?.status === 'PENDING_PAYMENT';

      record(
        9,
        'رد Authority جعلی و نامرتبط',
        passed9,
        `verifyStatus=${fakeVerify.status}, cbRedirect=${fakeCallback.headers.location}, orderStatus=${stored9?.status}`
      );
    } catch (e: any) {
      record(9, 'رد Authority جعلی', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۱۰: دستکاری مبلغ، تخفیف و ارسال (۱۵۰۰۰۰۰ threshold + server customFee)
    // ------------------------------------------------------------------------
    try {
      const tamperedRes = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری تست ۱۰',
          customerPhone: '09121010101',
          customerAddress: 'تهران، الهیه، پلاک ۱۰',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911110',
          paymentMethod: 'gateway',
          promoCode: 'PAYTEST10',
          items: [
            {
              productId: prodRegular.id,
              quantity: 2,
              customization: { customFee: 100000 } // Client fee ignored -> server 150,000 -> unit 1,050,000 * 2 = 2,100,000
            }
          ],
          total: 500000 // Tampered total instead of 1,890,000
        });

      const validCustomizedRes = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری تست ۱۰ معتبر',
          customerPhone: '09121010102',
          customerAddress: 'تهران، الهیه، پلاک ۱۰',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911110',
          paymentMethod: 'gateway',
          promoCode: 'PAYTEST10',
          items: [
            {
              productId: prodRegular.id,
              quantity: 2,
              customization: { customFee: 1 } // Client fee ignored -> 150,000 => subtotal 2,100,000 - 210,000 = 1,890,000
            }
          ],
          total: 1890000
        });
      if (validCustomizedRes.body?.id) createdOrderIds.push(validCustomizedRes.body.id);

      const passed10 =
        tamperedRes.status === 400 &&
        validCustomizedRes.status === 201 &&
        validCustomizedRes.body?.subtotal === 2100000 &&
        validCustomizedRes.body?.discount === 210000 &&
        validCustomizedRes.body?.shipping === 0 &&
        validCustomizedRes.body?.total === 1890000 &&
        validCustomizedRes.body?.items?.[0]?.customFee === 150000;

      record(
        10,
        'محاسبه سرور مبلغ/کارمزد/تخفیف/ارسال و رد دستکاری کلاینت',
        passed10,
        `tamperedStatus=${tamperedRes.status}, validTotal=${validCustomizedRes.body?.total}, customFee=${validCustomizedRes.body?.items?.[0]?.customFee}`
      );
    } catch (e: any) {
      record(10, 'رد دستکاری مبلغ', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۱۱: تغییر Order ID / IDOR (تایید یا درخواست با سفارش و توکن کاربر دیگر)
    // ------------------------------------------------------------------------
    try {
      const auth11 = 'S00000000000000000000000000000011111';
      setZarinPalTestTransport(async () => ({
        ok: true,
        status: 200,
        json: { data: { code: 100, authority: auth11 } }
      }));

      const orderA = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'کاربر الف',
          customerPhone: '09121110001',
          customerAddress: 'تهران، شهرک غرب، پلاک ۱',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911121',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      const orderB = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'کاربر ب',
          customerPhone: '09121110002',
          customerAddress: 'تهران، شهرک غرب، پلاک ۲',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911122',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      createdOrderIds.push(orderA.body.id, orderB.body.id);

      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', orderB.body.paymentToken)
        .send({ orderNumber: orderB.body.orderNumber });

      // Attacker uses Order A's paymentToken to request/verify Order B
      const idorReq = await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', orderA.body.paymentToken)
        .send({ orderNumber: orderB.body.orderNumber });

      const idorVerify = await request(app)
        .post('/api/payments/zarinpal/verify')
        .set('X-Payment-Token', orderA.body.paymentToken)
        .send({ orderNumber: orderB.body.orderNumber, authority: auth11 });

      const crossOrderAuthority = await request(app)
        .post('/api/payments/zarinpal/verify')
        .set('X-Payment-Token', orderA.body.paymentToken)
        .send({ orderNumber: orderA.body.orderNumber, authority: auth11 });

      const passed11 =
        idorReq.status === 403 &&
        idorVerify.status === 403 &&
        crossOrderAuthority.status === 400;

      record(
        11,
        'دفاع IDOR و جلوگیری از سوءاستفاده با Order ID یا Authority دیگران',
        passed11,
        `idorReq=${idorReq.status}, idorVerify=${idorVerify.status}, crossAuthority=${crossOrderAuthority.status}`
      );
    } catch (e: any) {
      record(11, 'دفاع IDOR', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۱۲: پرداخت هم‌زمان (Concurrent Callback + Verify) -> کاهش موجودی دقیقاً یک بار
    // ------------------------------------------------------------------------
    try {
      const auth12 = 'S00000000000000000000000000000012121';
      let verifyCount12 = 0;

      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/request.json')) {
          return { ok: true, status: 200, json: { data: { code: 100, authority: auth12 } } };
        }
        verifyCount12++;
        await new Promise((r) => setTimeout(r, 60));
        return {
          ok: true,
          status: 200,
          json: { data: { code: 100, ref_id: 121212, card_pan: '6037-99**-****-1212' } }
        };
      });

      const stockBefore12 = prodRegular.stock;
      const order12 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری هم‌زمان',
          customerPhone: '09121212121',
          customerAddress: 'تهران، یوسف‌آباد، پلاک ۱۲',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911125',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 2 }], // 1,800,000 Toman
          total: 1800000
        });
      createdOrderIds.push(order12.body.id);

      const reqPair = await Promise.all([
        request(app)
          .post('/api/payments/zarinpal/request')
          .set('X-Payment-Token', order12.body.paymentToken)
          .send({ orderNumber: order12.body.orderNumber, idempotencyKey: 'idem-concurrent-12' }),
        request(app)
          .post('/api/payments/zarinpal/request')
          .set('X-Payment-Token', order12.body.paymentToken)
          .send({ orderNumber: order12.body.orderNumber, idempotencyKey: 'idem-concurrent-12' })
      ]);

      const verifyPair = await Promise.all([
        request(app).get(`/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth12)}&Status=OK`),
        request(app)
          .post('/api/payments/zarinpal/verify')
          .set('X-Payment-Token', order12.body.paymentToken)
          .send({ orderNumber: order12.body.orderNumber, authority: auth12 })
      ]);

      const stored12 = dbOrders.find((o) => o.id === order12.body.id);
      const passed12 =
        reqPair.every((r) => r.status === 200 && r.body.authority === auth12) &&
        verifyPair[0].status === 302 &&
        verifyPair[1].status === 200 &&
        verifyCount12 === 1 &&
        stored12?.status === 'PAID' &&
        stored12?.inventoryDeducted === true &&
        prodRegular.stock === stockBefore12 - 2;

      record(
        12,
        'درخواست‌های هم‌زمان (Concurrency Lock & Single Inventory Decrement)',
        passed12,
        `verifyCalls=${verifyCount12}, stockBefore=${stockBefore12}, stockAfter=${prodRegular.stock}`
      );
    } catch (e: any) {
      record(12, 'درخواست‌های هم‌زمان', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۱۳: قطع ارتباط / Timeout روی Verify -> Pending Verify + بازیابی امن
    // ------------------------------------------------------------------------
    try {
      const auth13 = 'S00000000000000000000000000000013131';
      let mode13: 'timeout' | 'recover' = 'timeout';

      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/request.json')) {
          return { ok: true, status: 200, json: { data: { code: 100, authority: auth13 } } };
        }
        if (mode13 === 'timeout') {
          const err = new Error('The operation was aborted due to timeout');
          err.name = 'AbortError';
          throw err;
        }
        return {
          ok: true,
          status: 200,
          json: { data: { code: 100, ref_id: 131313, card_pan: '6037-99**-****-1313' } }
        };
      });

      const stockBefore13 = prodRegular.stock;
      const order13 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری تایم‌اوت',
          customerPhone: '09121313131',
          customerAddress: 'تهران، مرزداران، پلاک ۱۳',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911131',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      createdOrderIds.push(order13.body.id);

      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order13.body.paymentToken)
        .send({ orderNumber: order13.body.orderNumber });

      const cbTimeout = await request(app).get(
        `/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth13)}&Status=OK`
      );
      const pendingRef = dbOrders.find((o) => o.id === order13.body.id);
      const pendingStatus = pendingRef?.status;
      const pendingPaymentStatus = pendingRef?.paymentStatus;
      const pendingAttemptStatus = pendingRef?.paymentAttempts?.[0]?.status;
      const stockDuringPending = prodRegular.stock;

      // Now recover via manual re-verify endpoint
      mode13 = 'recover';
      const recoverRes = await request(app)
        .post('/api/payments/zarinpal/verify')
        .set('X-Payment-Token', order13.body.paymentToken)
        .send({ orderNumber: order13.body.orderNumber, authority: auth13 });
      const afterRecover = dbOrders.find((o) => o.id === order13.body.id);

      const passed13 =
        cbTimeout.status === 302 &&
        cbTimeout.headers.location ===
          `/?payment=pending_verify&orderNumber=${order13.body.orderNumber}` &&
        pendingStatus === 'PENDING_PAYMENT' &&
        pendingPaymentStatus === 'PENDING_VERIFY' &&
        pendingAttemptStatus === 'AMBIGUOUS' &&
        stockDuringPending === stockBefore13 &&
        recoverRes.status === 200 &&
        recoverRes.body?.refId === '131313' &&
        afterRecover?.status === 'PAID' &&
        afterRecover?.paymentStatus === 'SUCCESS' &&
        prodRegular.stock === stockBefore13 - 1;

      record(
        13,
        'Timeout / قطع ارتباط مبهم (Pending Verify) و بازیابی موفق',
        passed13,
        `timeoutRedirect=${cbTimeout.headers.location}, recoverRef=${recoverRes.body?.refId}, stock=${prodRegular.stock}`
      );
    } catch (e: any) {
      record(13, 'Timeout و بازیابی امن', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۱۴: موجودی صفر -> جلوگیری از ثبت سفارش و پرداخت
    // ------------------------------------------------------------------------
    try {
      const zeroOrderRes = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری کالای ناموجود',
          customerPhone: '09121414141',
          customerAddress: 'تهران، امیرآباد، پلاک ۱۴',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911141',
          paymentMethod: 'gateway',
          items: [{ productId: prodZeroStock.id, quantity: 1 }],
          total: 445000
        });

      const passed14 =
        zeroOrderRes.status === 400 &&
        typeof zeroOrderRes.body?.error === 'string' &&
        zeroOrderRes.body.error.includes('موجودی');

      record(
        14,
        'مسدودسازی سفارش محصول با موجودی صفر',
        passed14,
        `http=${zeroOrderRes.status}, msg=${zeroOrderRes.body?.error}`
      );
    } catch (e: any) {
      record(14, 'موجودی صفر', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۱۵ (B4): سفارش لغوشده با پرداخت موفق در درگاه -> verify + CANCELLED + needsReview + بدون کسر موجودی
    // ------------------------------------------------------------------------
    try {
      const auth15 = 'S00000000000000000000000000000015151';
      let verifyCalled15 = false;
      const stockBefore15 = prodRegular.stock;
      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/request.json')) {
          return { ok: true, status: 200, json: { data: { code: 100, authority: auth15 } } };
        }
        verifyCalled15 = true;
        return { ok: true, status: 200, json: { data: { code: 100, ref_id: 999999 } } };
      });

      const order15 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری لغوشده',
          customerPhone: '09121515151',
          customerAddress: 'تهران، پونک، پلاک ۱۵',
          province: 'تهران',
          city: 'تهران',
          postalCode: '1964911151',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      createdOrderIds.push(order15.body.id);

      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order15.body.paymentToken)
        .send({ orderNumber: order15.body.orderNumber });

      // Admin cancels order before bank callback
      const cancelRes = await request(app)
        .put(`/api/orders/${order15.body.id}/status`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ status: 'CANCELLED' });

      const cbCancelled = await request(app).get(
        `/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth15)}&Status=OK`
      );
      const stored15 = dbOrders.find((o) => o.id === order15.body.id);

      const passed15 =
        cancelRes.status === 200 &&
        cbCancelled.status === 302 &&
        cbCancelled.headers.location ===
          `/?payment=failed&reason=paid_after_cancel&orderNumber=${order15.body.orderNumber}` &&
        verifyCalled15 &&
        stored15?.status === 'CANCELLED' &&
        stored15?.paymentStatus === 'SUCCESS' &&
        stored15?.paymentInfo?.refId === '999999' &&
        stored15?.needsReview === true &&
        stored15?.reviewReason === 'PAID_AFTER_CANCEL' &&
        prodRegular.stock === stockBefore15;

      record(
        15,
        'سفارش لغوشده با پرداخت موفق بانکی -> تایید و ثبت paid_after_cancel با needsReview بدون کسر موجودی (B4)',
        passed15,
        `cancelStatus=${cancelRes.status}, verifyCalled=${verifyCalled15}, cbRedirect=${cbCancelled.headers.location}, orderStatus=${stored15?.status}, needsReview=${stored15?.needsReview}, reason=${stored15?.reviewReason}`
      );
    } catch (e: any) {
      record(15, 'سفارش لغوشده با پرداخت موفق بانکی (B4)', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۱۷ (A1): کارمزد طراحی اختصاصی سمت سرور، customizationFee محصول و رد محصول غیرقابل‌سفارشی‌سازی
    // ------------------------------------------------------------------------
    const prodCustomFeeOverride = {
      id: 'prod-pay-test-custom-override',
      name: 'هودی با کارمزد اختصاصی',
      price: 1000000,
      stock: 5,
      status: 'published',
      isCustomizable: true,
      customizationFee: 220000
    };
    const prodNoCustom = {
      id: 'prod-pay-test-no-custom',
      name: 'اکسسوری بدون چاپ',
      price: 300000,
      stock: 5,
      status: 'published',
      customizable: false
    };
    dbProducts.push(prodCustomFeeOverride, prodNoCustom);
    try {
      const feeZeroAttempt = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'تست دستکاری کارمزد',
          customerPhone: '09121717171',
          customerAddress: 'تهران، سعادت‌آباد، پلاک ۱۷',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1, customization: { customFee: 0 } }],
          total: 945000 // Attacker assumes customFee=0
        });

      const feeHighAttempt = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'تست کارمزد بالا',
          customerPhone: '09121717172',
          customerAddress: 'تهران، سعادت‌آباد، پلاک ۱۷',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1, customization: { customFee: 999999 } }],
          total: 900000 + 999999
        });

      const nonCustomizableAttempt = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'تست محصول غیرچاپی',
          customerPhone: '09121717173',
          customerAddress: 'تهران، سعادت‌آباد، پلاک ۱۷',
          paymentMethod: 'gateway',
          items: [{ productId: prodNoCustom.id, quantity: 1, customization: { customFee: 150000 } }]
        });

      const overrideProductRes = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'تست محصول با کارمزد اختصاصی',
          customerPhone: '09121717174',
          customerAddress: 'تهران، سعادت‌آباد، پلاک ۱۷',
          paymentMethod: 'gateway',
          items: [{ productId: prodCustomFeeOverride.id, quantity: 1, customization: { customFee: 1 } }],
          total: 1000000 + 220000 + 45000
        });
      if (overrideProductRes.body?.id) createdOrderIds.push(overrideProductRes.body.id);

      const passed17 =
        feeZeroAttempt.status === 400 &&
        feeHighAttempt.status === 400 &&
        nonCustomizableAttempt.status === 400 &&
        overrideProductRes.status === 201 &&
        overrideProductRes.body?.items?.[0]?.customFee === 220000 &&
        overrideProductRes.body?.total === 1265000;

      record(
        17,
        'کنترل قطعی کارمزد طراحی اختصاصی در سرور و رد محصول غیرقابل چاپ (A1)',
        passed17,
        `zero=${feeZeroAttempt.status}, high=${feeHighAttempt.status}, noCustom=${nonCustomizableAttempt.status}, overrideFee=${overrideProductRes.body?.items?.[0]?.customFee}`
      );
    } catch (e: any) {
      record(17, 'کارمزد طراحی اختصاصی سرور (A1)', false, e.message);
    } finally {
      for (const pid of [prodCustomFeeOverride.id, prodNoCustom.id]) {
        const i = dbProducts.findIndex((p) => p.id === pid);
        if (i !== -1) dbProducts.splice(i, 1);
      }
    }

    // ------------------------------------------------------------------------
    // تست ۱۸ (A4): نرمال‌سازی موبایل و اعتبارسنجی ایمیل پیش از ذخیره و ارسال به زرین‌پال
    // ------------------------------------------------------------------------
    try {
      let sentMeta18: any = null;
      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/request.json')) {
          sentMeta18 = req.body?.metadata;
          return { ok: true, status: 200, json: { data: { code: 100, authority: 'S00000000000000000000000000000018181' } } };
        }
        return { ok: true, status: 200, json: { data: { code: 100, ref_id: 181818 } } };
      });

      const invalidPhoneRes = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'کاربر موبایل نامعتبر',
          customerPhone: '08123456789',
          customerAddress: 'تهران، جردن، کوچه ۱۸',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }]
        });

      const normOrderRes = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'کاربر موبایل بین‌المللی و ایمیل نامعتبر',
          customerPhone: '+۹۸۹۱۲۳۴۵۶۷۸۹',
          customerEmail: 'not-a-valid-email@',
          customerAddress: 'تهران، جردن، کوچه ۱۸',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      if (normOrderRes.body?.id) createdOrderIds.push(normOrderRes.body.id);

      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', normOrderRes.body.paymentToken)
        .send({ orderNumber: normOrderRes.body.orderNumber });

      const passed18 =
        invalidPhoneRes.status === 400 &&
        normOrderRes.status === 201 &&
        normOrderRes.body?.customerPhone === '09123456789' &&
        normOrderRes.body?.customerEmail === undefined &&
        sentMeta18?.mobile === '09123456789' &&
        sentMeta18?.email === undefined;

      record(
        18,
        'نرمال‌سازی موبایل و حذف ایمیل نامعتبر از سفارش و metadata زرین‌پال (A4)',
        passed18,
        `invalidPhone=${invalidPhoneRes.status}, normalized=${normOrderRes.body?.customerPhone}, metaEmail=${sentMeta18?.email}`
      );
    } catch (e: any) {
      record(18, 'نرمال‌سازی موبایل و ایمیل (A4)', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۱۹ (A5): تعارض موجودی پس از Verify (Oversell) -> needsReview=true + INSUFFICIENT_STOCK + لاگ critical
    // ------------------------------------------------------------------------
    const prodSingleStock = {
      id: 'prod-pay-test-single-stock',
      name: 'تیشرت تک‌عدد تستی Oversell',
      price: 500000,
      stock: 1,
      status: 'published',
      customizable: false
    };
    dbProducts.push(prodSingleStock);
    try {
      const auth19a = 'S00000000000000000000000000000019191';
      const auth19b = 'S00000000000000000000000000000019192';
      let reqIdx19 = 0;
      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/request.json')) {
          reqIdx19++;
          return { ok: true, status: 200, json: { data: { code: 100, authority: reqIdx19 === 1 ? auth19a : auth19b } } };
        }
        return { ok: true, status: 200, json: { data: { code: 100, ref_id: 190000 + reqIdx19 } } };
      });

      const order19a = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'خریدار اول تک‌عدد',
          customerPhone: '09121919191',
          customerAddress: 'تهران، ونک، پلاک ۱۹',
          paymentMethod: 'gateway',
          items: [{ productId: prodSingleStock.id, quantity: 1 }],
          total: 545000
        });
      const order19b = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'خریدار دوم هم‌زمان',
          customerPhone: '09121919192',
          customerAddress: 'تهران، ونک، پلاک ۲۰',
          paymentMethod: 'gateway',
          items: [{ productId: prodSingleStock.id, quantity: 1 }],
          total: 545000
        });
      createdOrderIds.push(order19a.body.id, order19b.body.id);

      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order19a.body.paymentToken)
        .send({ orderNumber: order19a.body.orderNumber });
      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order19b.body.paymentToken)
        .send({ orderNumber: order19b.body.orderNumber });

      // Buyer A pays first (stock 1 -> 0)
      await request(app).get(`/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth19a)}&Status=OK`);
      // Buyer B also completed payment before stock hit 0
      await request(app).get(`/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth19b)}&Status=OK`);

      const stored19a = dbOrders.find((o) => o.id === order19a.body.id);
      const stored19b = dbOrders.find((o) => o.id === order19b.body.id);
      const hasCriticalOversellLog = getRecentAuditLogs().some(
        (l) => l.severity === 'critical' && l.details.includes('INSUFFICIENT_STOCK') && l.details.includes(stored19b?.orderNumber)
      );

      const passed19 =
        stored19a?.status === 'PAID' &&
        !stored19a?.needsReview &&
        stored19b?.status === 'PAID' &&
        stored19b?.needsReview === true &&
        stored19b?.reviewReason === 'INSUFFICIENT_STOCK' &&
        prodSingleStock.stock === 0 &&
        hasCriticalOversellLog;

      record(
        19,
        'علامت‌گذاری سفارش در تعارض موجودی (INSUFFICIENT_STOCK) و ثبت لاگ بحرانی (A5)',
        passed19,
        `needsReview=${stored19b?.needsReview}, reason=${stored19b?.reviewReason}, criticalLog=${hasCriticalOversellLog}`
      );
    } catch (e: any) {
      record(19, 'تعارض موجودی بعد از پرداخت (A5)', false, e.message);
    } finally {
      const idx = dbProducts.findIndex((p) => p.id === prodSingleStock.id);
      if (idx !== -1) dbProducts.splice(idx, 1);
    }

    // ------------------------------------------------------------------------
    // تست ۲۰ (A6): Reconciler پس‌زمینه برای تعیین تکلیف پرداخت رهاشده و لغو سفارش قدیمی
    // ------------------------------------------------------------------------
    try {
      const auth20 = 'S00000000000000000000000000000020201';
      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/request.json')) {
          return { ok: true, status: 200, json: { data: { code: 100, authority: auth20 } } };
        }
        return { ok: true, status: 200, json: { data: { code: 100, ref_id: 202020, card_pan: '6219-86**-****-2020' } } };
      });

      const order20PaidNoCb = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری قطع‌شده قبل از callback',
          customerPhone: '09122020201',
          customerAddress: 'تهران، نیاوران، پلاک ۲۰',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      const order20Abandoned = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری رهاکننده ۲۴ ساعته',
          customerPhone: '09122020202',
          customerAddress: 'تهران، نیاوران، پلاک ۲۱',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      createdOrderIds.push(order20PaidNoCb.body.id, order20Abandoned.body.id);

      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order20PaidNoCb.body.paymentToken)
        .send({ orderNumber: order20PaidNoCb.body.orderNumber });

      // Backdate attempt & order dates for deterministic reconciler execution
      const ref20a = dbOrders.find((o) => o.id === order20PaidNoCb.body.id);
      const ref20b = dbOrders.find((o) => o.id === order20Abandoned.body.id);
      if (ref20a?.paymentAttempts?.[0]) {
        ref20a.paymentAttempts[0].createdAt = new Date(Date.now() - 10 * 60 * 1000).toISOString();
      }
      if (ref20b) {
        ref20b.date = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString();
      }

      const recSummary = await runPaymentReconciler();

      const passed20 =
        recSummary.verified >= 1 &&
        recSummary.expiredCancelled >= 1 &&
        ref20a?.status === 'PAID' &&
        ref20a?.paymentInfo?.refId === '202020' &&
        ref20b?.status === 'CANCELLED' &&
        ref20b?.paymentStatus === 'EXPIRED';

      record(
        20,
        'تطبیق‌دهنده پس‌زمینه (Verify تراکنش رهاشده + لغو سفارش بدون پرداخت ۲۴ ساعته) (A6)',
        passed20,
        `verified=${recSummary.verified}, cancelled=${recSummary.expiredCancelled}, statusA=${ref20a?.status}, statusB=${ref20b?.status}`
      );
    } catch (e: any) {
      record(20, 'تطبیق‌دهنده پس‌زمینه (A6)', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۲۱ (A7): مصرف کد تخفیف فقط در پرداخت موفق + بررسی انقضا/سقف و percent در validate
    // ------------------------------------------------------------------------
    const singleUsePromo = {
      id: 'disc-a7-test',
      code: 'LIMITED20',
      type: 'percentage',
      percent: 20, // Deliberately no `amount` field to verify validate alignment
      active: true,
      maxUses: 1,
      usedCount: 0,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    };
    const expiredPromo = {
      id: 'disc-a7-expired',
      code: 'EXPIRED50',
      type: 'percentage',
      percent: 50,
      active: true,
      expiresAt: new Date(Date.now() - 60 * 1000).toISOString()
    };
    dbDiscounts.push(singleUsePromo, expiredPromo);
    try {
      const auth21 = 'S00000000000000000000000000000021211';
      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/request.json')) {
          return { ok: true, status: 200, json: { data: { code: 100, authority: auth21 } } };
        }
        return { ok: true, status: 200, json: { data: { code: 100, ref_id: 212121 } } };
      });

      const valPercentRes = await request(app)
        .post('/api/discounts/validate')
        .send({ code: 'LIMITED20', subtotal: 900000 });
      const valExpiredRes = await request(app)
        .post('/api/discounts/validate')
        .send({ code: 'EXPIRED50', subtotal: 900000 });

      // Create unpaid order with LIMITED20 -> usedCount MUST remain 0
      const order21 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری تخفیف یک‌بارمصرف',
          customerPhone: '09122121211',
          customerAddress: 'تهران، پاسداران، پلاک ۲۱',
          paymentMethod: 'gateway',
          promoCode: 'LIMITED20',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 900000 - 180000 + 45000 // 765,000
        });
      if (order21.body?.id) createdOrderIds.push(order21.body.id);

      const usedBeforePay = singleUsePromo.usedCount;
      const valBeforePay = await request(app)
        .post('/api/discounts/validate')
        .send({ code: 'LIMITED20', subtotal: 900000 });

      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order21.body.paymentToken)
        .send({ orderNumber: order21.body.orderNumber });
      await request(app).get(`/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth21)}&Status=OK`);

      const usedAfterPay = singleUsePromo.usedCount;
      const valAfterPay = await request(app)
        .post('/api/discounts/validate')
        .send({ code: 'LIMITED20', subtotal: 900000 });

      const passed21 =
        valPercentRes.body?.valid === true &&
        valPercentRes.body?.discountAmount === 180000 &&
        valExpiredRes.body?.valid === false &&
        order21.status === 201 &&
        usedBeforePay === 0 &&
        valBeforePay.body?.valid === true &&
        usedAfterPay === 1 &&
        valAfterPay.body?.valid === false;

      record(
        21,
        'مصرف سهمیه تخفیف فقط در پرداخت موفق و هم‌ترازی validate (انقضا/سقف/درصد) (A7)',
        passed21,
        `percentAmt=${valPercentRes.body?.discountAmount}, expired=${valExpiredRes.body?.valid}, before=${usedBeforePay}, after=${usedAfterPay}, afterVal=${valAfterPay.body?.valid}`
      );
    } catch (e: any) {
      record(21, 'سهمیه کد تخفیف و validate (A7)', false, e.message);
    } finally {
      for (const id of [singleUsePromo.id, expiredPromo.id]) {
        const i = dbDiscounts.findIndex((d) => d.id === id);
        if (i !== -1) dbDiscounts.splice(i, 1);
      }
    }

    // ------------------------------------------------------------------------
    // تست ۲۲ (A8): دسته‌بندی خطاهای مبهم (429 / 5xx+JSON / -12 / -52) و جلوگیری از پرداخت دوبل قبل از Retry
    // ------------------------------------------------------------------------
    try {
      const auth22 = 'S00000000000000000000000000000022221';
      let verifyPhase22: '429' | '500_json' | 'code_neg12' | 'code_neg52' | 'missing_code' | 'success' = '429';
      let reqCalls22 = 0;

      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/request.json')) {
          reqCalls22++;
          return { ok: true, status: 200, json: { data: { code: 100, authority: auth22 } } };
        }
        if (verifyPhase22 === '429') return { ok: false, status: 429, json: { message: 'Too Many Requests' } };
        if (verifyPhase22 === '500_json') return { ok: false, status: 500, json: { errors: { code: -52, message: 'Server error' } } };
        if (verifyPhase22 === 'code_neg12') return { ok: false, status: 400, json: { errors: { code: -12 } } };
        if (verifyPhase22 === 'code_neg52') return { ok: false, status: 400, json: { errors: { code: -52 } } };
        if (verifyPhase22 === 'missing_code') return { ok: true, status: 200, json: { data: {} } };
        return { ok: true, status: 200, json: { data: { code: 100, ref_id: 222222 } } };
      });

      const v429 = await verifyZarinPalTransaction({ authority: auth22, amountToman: 945000, merchantId: TEST_MERCHANT_UUID, mode: 'sandbox' });
      verifyPhase22 = '500_json';
      const v500Json = await verifyZarinPalTransaction({ authority: auth22, amountToman: 945000, merchantId: TEST_MERCHANT_UUID, mode: 'sandbox' });
      verifyPhase22 = 'code_neg12';
      const vNeg12 = await verifyZarinPalTransaction({ authority: auth22, amountToman: 945000, merchantId: TEST_MERCHANT_UUID, mode: 'sandbox' });
      verifyPhase22 = 'code_neg52';
      const vNeg52 = await verifyZarinPalTransaction({ authority: auth22, amountToman: 945000, merchantId: TEST_MERCHANT_UUID, mode: 'sandbox' });
      verifyPhase22 = 'missing_code';
      const vMissing = await verifyZarinPalTransaction({ authority: auth22, amountToman: 945000, merchantId: TEST_MERCHANT_UUID, mode: 'sandbox' });

      // Test verify-before-retry when an order has an AMBIGUOUS attempt
      const order22 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری پیشگیری پرداخت دوبل',
          customerPhone: '09122222221',
          customerAddress: 'تهران، یوسف‌آباد، پلاک ۲۲',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      if (order22.body?.id) createdOrderIds.push(order22.body.id);

      await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order22.body.paymentToken)
        .send({ orderNumber: order22.body.orderNumber });

      // Simulate callback receiving -52 (ambiguous)
      verifyPhase22 = 'code_neg52';
      await request(app).get(`/api/payments/zarinpal/callback?Authority=${encodeURIComponent(auth22)}&Status=OK`);

      // User retries /request while bank actually succeeded -> server must verify AMBIGUOUS attempt first and block double pay with 409
      verifyPhase22 = 'success';
      const reqCallsBeforeRetry = reqCalls22;
      const retryBlockedRes = await request(app)
        .post('/api/payments/zarinpal/request')
        .set('X-Payment-Token', order22.body.paymentToken)
        .send({ orderNumber: order22.body.orderNumber });

      const stored22 = dbOrders.find((o) => o.id === order22.body.id);

      const passed22 =
        v429.ambiguous === true &&
        v500Json.ambiguous === true &&
        vNeg12.ambiguous === true &&
        vNeg52.ambiguous === true &&
        vMissing.ambiguous === true &&
        retryBlockedRes.status === 409 &&
        retryBlockedRes.body?.alreadyPaid === true &&
        reqCalls22 === reqCallsBeforeRetry &&
        stored22?.status === 'PAID' &&
        stored22?.paymentInfo?.refId === '222222';

      record(
        22,
        'دسته‌بندی خطاهای مبهم verify و جلوگیری از پرداخت دوبل پیش از صدور Authority جدید (A8)',
        passed22,
        `ambiguous=[${v429.ambiguous},${v500Json.ambiguous},${vNeg12.ambiguous},${vNeg52.ambiguous},${vMissing.ambiguous}], retryStatus=${retryBlockedRes.status}, orderStatus=${stored22?.status}`
      );
    } catch (e: any) {
      record(22, 'خطاهای مبهم و پیشگیری از پرداخت دوبل (A8)', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۲۳ (B2): حذف کامل fallback موبایل از مسیرهای پرداخت و سلامت /orders/track
    // ------------------------------------------------------------------------
    try {
      const order23 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری تست توکن ۲۳',
          customerPhone: '09122323231',
          customerAddress: 'تهران، سعادت‌آباد، پلاک ۲۳',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      createdOrderIds.push(order23.body.id);

      // Phone in query or body MUST NOT authorize payment endpoints
      const resNoToken = await request(app).get(
        `/api/payments/orders/${encodeURIComponent(order23.body.orderNumber)}/result?phone=09122323231`
      );
      const reqWithPhoneOnly = await request(app)
        .post('/api/payments/zarinpal/request')
        .send({ orderNumber: order23.body.orderNumber, phone: '09122323231' });
      const resWithToken = await request(app)
        .get(`/api/payments/orders/${encodeURIComponent(order23.body.orderNumber)}/result`)
        .set('X-Payment-Token', order23.body.paymentToken);
      const trackOk = await request(app)
        .post('/api/orders/track')
        .send({ orderNumber: order23.body.orderNumber, phone: '09122323231' });

      const passed23 =
        resNoToken.status === 401 &&
        resNoToken.body?.trackingRequired === true &&
        reqWithPhoneOnly.status === 403 &&
        resWithToken.status === 200 &&
        resWithToken.body?.order?.orderNumber === order23.body.orderNumber &&
        trackOk.status === 200;

      record(
        23,
        'حذف fallback شماره تماس از مسیرهای پرداخت و راهنمایی به پیگیری سفارش (B2)',
        passed23,
        `resultNoTok=${resNoToken.status}, reqPhoneOnly=${reqWithPhoneOnly.status}, resultTok=${resWithToken.status}, track=${trackOk.status}`
      );
    } catch (e: any) {
      record(23, 'حذف fallback شماره تماس (B2)', false, e.message);
    }

    // ------------------------------------------------------------------------
    // تست ۲۴ (B3 + A6): سقف ۳ سفارش PENDING_PAYMENT برای هر موبایل و لغو ۷۲ ساعته کارت‌به‌کارت + بازگشت تخفیف
    // ------------------------------------------------------------------------
    const cardPromo = {
      id: 'disc-b3-card-promo',
      code: 'CARDPROMO72',
      type: 'percentage',
      percent: 10,
      active: true,
      usedCount: 0,
      maxUses: 5
    };
    dbDiscounts.push(cardPromo);
    try {
      const pendingPhone = '09122424241';
      const p1 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'سفارش اول',
          customerPhone: pendingPhone,
          customerAddress: 'تهران، ولیعصر، ۱',
          paymentMethod: 'card',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      const p2 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'سفارش دوم',
          customerPhone: '+989122424241', // Normalized to same phone!
          customerAddress: 'تهران، ولیعصر، ۲',
          paymentMethod: 'card',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      const p3 = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'سفارش سوم',
          customerPhone: pendingPhone,
          customerAddress: 'تهران، ولیعصر، ۳',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      const p4Blocked = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'سفارش چهارم اضافه',
          customerPhone: pendingPhone,
          customerAddress: 'تهران، ولیعصر، ۴',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      [p1, p2, p3].forEach((r) => r.body?.id && createdOrderIds.push(r.body.id));

      // Verify card order NOT cancelled at 25h, cancelled at 73h + promoCounted quota restored
      const cardRef = dbOrders.find((o) => o.id === p1.body.id);
      cardRef.promoCode = 'CARDPROMO72';
      cardRef.promoCounted = true;
      cardPromo.usedCount = 1;
      cardRef.date = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString();
      await runPaymentReconciler();
      const statusAt25h = cardRef.status;

      cardRef.date = new Date(Date.now() - 73 * 60 * 60 * 1000).toISOString();
      await runPaymentReconciler();
      const statusAt73h = cardRef.status;
      const quotaAfter73h = cardPromo.usedCount;

      const passed24 =
        p1.status === 201 &&
        p2.status === 201 &&
        p3.status === 201 &&
        p4Blocked.status === 429 &&
        statusAt25h === 'PENDING_PAYMENT' &&
        statusAt73h === 'CANCELLED' &&
        quotaAfter73h === 0;

      record(
        24,
        'سقف ۳ سفارش PENDING_PAYMENT و لغو ۷۲ ساعته کارت‌به‌کارت با بازگشت سهمیه تخفیف (B3)',
        passed24,
        `p4=${p4Blocked.status}, card25h=${statusAt25h}, card73h=${statusAt73h}, promoUsed=${quotaAfter73h}`
      );
    } catch (e: any) {
      record(24, 'سقف ۳ سفارش PENDING و لغو ۷۲ ساعته (B3)', false, e.message);
    } finally {
      const di = dbDiscounts.findIndex((d) => d.id === cardPromo.id);
      if (di !== -1) dbDiscounts.splice(di, 1);
    }

    // ------------------------------------------------------------------------
    // تست ۲۵ (B3): ذخیره‌سازی تصاویر طراحی سفارشی به‌صورت فایل در UPLOADS_DIR/designs و مسدودیت SVG
    // ------------------------------------------------------------------------
    const createdDesignFiles: string[] = [];
    try {
      const tinyPngBase64 =
        'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';
      const svgBase64 =
        'data:image/png;base64,' + Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>').toString('base64');

      const svgOrderAttempt = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مهاجم SVG طراحی',
          customerPhone: '09122525251',
          customerAddress: 'تهران، نیاوران، پلاک ۲۵',
          paymentMethod: 'gateway',
          items: [
            {
              productId: prodRegular.id,
              quantity: 1,
              customization: {
                designImageUrl: svgBase64
              }
            }
          ]
        });

      const designOrderRes = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری طراح اختصاصی',
          customerPhone: '09122525252',
          customerAddress: 'تهران، جردن، پلاک ۲۵',
          paymentMethod: 'gateway',
          items: [
            {
              productId: prodRegular.id,
              quantity: 1,
              customization: {
                designImageUrl: tinyPngBase64,
                previewMockupUrl: tinyPngBase64,
                views: {
                  front: {
                    viewId: 'front',
                    viewTitle: 'رو',
                    layers: [{ id: 'l1', type: 'image', content: tinyPngBase64, x: 50, y: 50 }],
                    designImageUrl: tinyPngBase64
                  }
                }
              }
            }
          ],
          total: 900000 + 150000 + 45000
        });
      if (designOrderRes.body?.id) createdOrderIds.push(designOrderRes.body.id);

      const savedDesignUrl: string = designOrderRes.body?.items?.[0]?.customization?.designImageUrl || '';
      const savedViewUrl: string =
        designOrderRes.body?.items?.[0]?.customization?.views?.front?.designImageUrl || '';
      const expectedFilename = path.basename(savedDesignUrl);
      const diskPath = path.join(DESIGN_UPLOADS_DIR, expectedFilename);
      if (savedDesignUrl.startsWith('/uploads/designs/') && fs.existsSync(diskPath)) {
        createdDesignFiles.push(diskPath);
      }

      const passed25 =
        svgOrderAttempt.status === 400 &&
        designOrderRes.status === 201 &&
        savedDesignUrl.startsWith('/uploads/designs/design_') &&
        savedViewUrl === savedDesignUrl &&
        !JSON.stringify(designOrderRes.body?.items?.[0]?.customization).includes('data:image/') &&
        fs.existsSync(diskPath);

      record(
        25,
        'ذخیره‌سازی فایل تصاویر طراحی سفارش در UPLOADS_DIR/designs و رد SVG (B3)',
        passed25,
        `svgBlocked=${svgOrderAttempt.status}, savedUrl=${savedDesignUrl}, exists=${fs.existsSync(diskPath)}`
      );
    } catch (e: any) {
      record(25, 'ذخیره‌سازی فایل تصاویر طراحی (B3)', false, e.message);
    } finally {
      for (const f of createdDesignFiles) {
        try {
          if (fs.existsSync(f)) fs.unlinkSync(f);
        } catch {}
      }
    }

    // ------------------------------------------------------------------------
    // تست ۲۶ (B6): الزام تایید و دلیل مشخص هنگام ارتقای دستی سفارش درگاهی فاقد RefID به PAID
    // ------------------------------------------------------------------------
    try {
      const gwUnpaid = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری ارتقای دستی درگاهی',
          customerPhone: '09122626261',
          customerAddress: 'تهران، سعادت‌آباد، پلاک ۲۶',
          paymentMethod: 'gateway',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      const cardUnpaid = await request(app)
        .post('/api/orders')
        .set('X-Forwarded-For', nextOrderIp())
        .send({
          customerName: 'مشتری کارت‌به‌کارت عادی',
          customerPhone: '09122626262',
          customerAddress: 'تهران، سعادت‌آباد، پلاک ۲۷',
          paymentMethod: 'card',
          items: [{ productId: prodRegular.id, quantity: 1 }],
          total: 945000
        });
      createdOrderIds.push(gwUnpaid.body.id, cardUnpaid.body.id);

      const unconfirmedAttempt = await request(app)
        .put(`/api/orders/${gwUnpaid.body.id}/status`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ status: 'PAID' });

      const confirmedAttempt = await request(app)
        .put(`/api/orders/${gwUnpaid.body.id}/status`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          status: 'PAID',
          confirmManualPaid: true,
          reason: 'رسید شاپرک در تیکت پشتیبانی تأیید شد'
        });

      const cardNormalAttempt = await request(app)
        .put(`/api/orders/${cardUnpaid.body.id}/status`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ status: 'PAID' });

      const hasWarningAudit = getRecentAuditLogs().some(
        (l) => l.severity === 'warning' && l.details.includes(gwUnpaid.body.orderNumber) && l.details.includes('بدون RefID')
      );

      const passed26 =
        unconfirmedAttempt.status === 400 &&
        unconfirmedAttempt.body?.requireManualConfirmation === true &&
        confirmedAttempt.status === 200 &&
        confirmedAttempt.body?.manuallyMarkedPaid === true &&
        confirmedAttempt.body?.needsReview === true &&
        typeof confirmedAttempt.body?.manualPaidReason === 'string' &&
        cardNormalAttempt.status === 200 &&
        hasWarningAudit;

      record(
        26,
        'محافظ ارتقای دستی PAID بدون RefID برای درگاهی و سلامت کارت‌به‌کارت (B6)',
        passed26,
        `unconfirmed=${unconfirmedAttempt.status}, confirmed=${confirmedAttempt.status}, card=${cardNormalAttempt.status}, warnLog=${hasWarningAudit}`
      );
    } catch (e: any) {
      record(26, 'محافظ ارتقای دستی PAID (B6)', false, e.message);
    }
  } finally {
    setZarinPalTestTransport(null);

    // Clean in-memory test artifacts
    for (const oid of createdOrderIds) {
      const idx = dbOrders.findIndex((o) => o.id === oid);
      if (idx !== -1) dbOrders.splice(idx, 1);
    }
    for (const pid of [prodRegular.id, prodZeroStock.id]) {
      const idx = dbProducts.findIndex((p) => p.id === pid);
      if (idx !== -1) dbProducts.splice(idx, 1);
    }
    const dIdx = dbDiscounts.findIndex((d) => d.code === testDiscount.code);
    if (dIdx !== -1) dbDiscounts.splice(dIdx, 1);

    // Restore original persistent store file cleanly
    if (hadDataFile && originalDataSnapshot !== null) {
      fs.writeFileSync(DATA_FILE, originalDataSnapshot, 'utf8');
    } else if (!hadDataFile && fs.existsSync(DATA_FILE)) {
      fs.unlinkSync(DATA_FILE);
    }
  }

  console.log('\n========================================================================');
  const passedCount = results.filter((r) => r.passed).length;
  console.log(`خلاصه نتایج تست پرداخت زرین‌پال: ${passedCount} از ${results.length} تست با موفقیت پاس شد.`);
  console.log('========================================================================');

  if (passedCount !== results.length) {
    process.exit(1);
  }
  process.exit(0);
}

runPaymentTestSuite().catch((err) => {
  console.error('Fatal error in payment test suite:', err);
  process.exit(1);
});
