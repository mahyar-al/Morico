/**
 * Automated End-to-End ZarinPal IPG & Financial Security Test Suite
 * Covers all 16 mandatory payment, inventory, currency, state-machine, idempotency,
 * concurrency, timeout recovery, and security test scenarios using supertest.
 */

process.env.NODE_ENV = 'test';

import fs from 'fs';
import request from 'supertest';
import {
  app,
  dbProducts,
  dbOrders,
  dbUsers,
  dbDiscounts,
  signJoseToken,
  SESSION_SECRET
} from '../server';
import { DATA_FILE } from '../src/server/storage';
import {
  setZarinPalTestTransport,
  tomanToRial,
  type ZarinPalTransportRequest
} from '../src/server/payment';

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
    // تست ۱۰: دستکاری مبلغ، تخفیف و ارسال (۱۵۰۰۰۰۰ threshold + customization)
    // ------------------------------------------------------------------------
    try {
      const tamperedRes = await request(app)
        .post('/api/orders')
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
              quantity: 2, // 1,800,000 - 10% (180,000) = 1,620,000 (>= 1,500,000 -> shipping 0!)
              customization: { customFee: 100000 } // +200,000 -> subtotal 2,000,000 -> -200,000 = 1,800,000
            }
          ],
          total: 500000 // Tampered total instead of 1,800,000
        });

      const validCustomizedRes = await request(app)
        .post('/api/orders')
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
              customization: { customFee: 100000 }
            }
          ],
          total: 1800000
        });
      if (validCustomizedRes.body?.id) createdOrderIds.push(validCustomizedRes.body.id);

      const passed10 =
        tamperedRes.status === 400 &&
        validCustomizedRes.status === 201 &&
        validCustomizedRes.body?.subtotal === 2000000 &&
        validCustomizedRes.body?.discount === 200000 &&
        validCustomizedRes.body?.shipping === 0 &&
        validCustomizedRes.body?.total === 1800000;

      record(
        10,
        'محاسبه سرور مبلغ/تخفیف/ارسال و رد دستکاری کلاینت',
        passed10,
        `tamperedStatus=${tamperedRes.status}, validTotal=${validCustomizedRes.body?.total}, shipping=${validCustomizedRes.body?.shipping}`
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
    // تست ۱۵: سفارش لغوشده -> Callback موفق نباید سفارش CANCELLED را PAID کند
    // ------------------------------------------------------------------------
    try {
      const auth15 = 'S00000000000000000000000000000015151';
      let verifyCalled15 = false;
      setZarinPalTestTransport(async (req) => {
        if (req.url.endsWith('/request.json')) {
          return { ok: true, status: 200, json: { data: { code: 100, authority: auth15 } } };
        }
        verifyCalled15 = true;
        return { ok: true, status: 200, json: { data: { code: 100, ref_id: 999999 } } };
      });

      const order15 = await request(app)
        .post('/api/orders')
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

      // Admin cancels order
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
          `/?payment=failed&reason=order_cancelled&orderNumber=${order15.body.orderNumber}` &&
        !verifyCalled15 &&
        stored15?.status === 'CANCELLED';

      record(
        15,
        'جلوگیری از Paid شدن سفارش لغوشده در Callback',
        passed15,
        `cancelStatus=${cancelRes.status}, cbRedirect=${cbCancelled.headers.location}, orderStatus=${stored15?.status}`
      );
    } catch (e: any) {
      record(15, 'جلوگیری از Paid شدن سفارش لغوشده', false, e.message);
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
