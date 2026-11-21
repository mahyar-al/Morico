import { sanitizeText, cleanPhoneNumber, normalizeIranianMobile, normalizeAndValidateEmail } from './security';

export const DEFAULT_CUSTOMIZATION_FEE_TOMAN = 150000;

export function isProductCustomizable(product: any): boolean {
  return Boolean(product?.customizable || product?.allowCustomization || product?.isCustomizable);
}

export function getProductCustomizationFee(product: any): number {
  const raw = product?.customizationFee;
  if (raw !== undefined && raw !== null && raw !== '') {
    const num = Number(raw);
    if (Number.isFinite(num) && num >= 0 && num <= 5000000) {
      return Math.round(num);
    }
  }
  return DEFAULT_CUSTOMIZATION_FEE_TOMAN;
}

export function evaluateDiscountCode(
  discountList: any[],
  codeInput: string,
  subtotal: number,
  nowMs = Date.now()
):
  | {
      valid: true;
      discountObj: any;
      code: string;
      discountAmount: number;
      description?: string;
    }
  | { valid: false; error: string } {
  const cleanCode = String(codeInput || '').trim().toUpperCase();
  if (!cleanCode) {
    return { valid: false, error: 'کد تخفیف را وارد فرمایید.' };
  }

  const found = discountList.find((d) => String(d.code || '').trim().toUpperCase() === cleanCode && d.active !== false);
  if (!found) {
    return { valid: false, error: 'کد تخفیف معتبر نیست یا منقضی شده است.' };
  }

  const expiry = found.expiresAt || found.expiryDate;
  if (expiry) {
    const expTime = new Date(expiry).getTime();
    if (!Number.isNaN(expTime) && expTime < nowMs) {
      return { valid: false, error: 'مهلت استفاده از این کد تخفیف به پایان رسیده است.' };
    }
  }

  const maxUses = found.maxUses ?? found.usageLimit;
  const usedCount = found.usedCount ?? found.usageCount ?? 0;
  if (maxUses !== undefined && maxUses !== null && Number(maxUses) > 0 && Number(usedCount) >= Number(maxUses)) {
    return { valid: false, error: 'سقف مجاز استفاده از این کد تخفیف به پایان رسیده است.' };
  }

  const sub = Number.isFinite(Number(subtotal)) ? Math.max(0, Number(subtotal)) : 0;
  if (found.minOrderAmount && sub < Number(found.minOrderAmount)) {
    return {
      valid: false,
      error: `حداقل مبلغ خرید برای این کد ${Number(found.minOrderAmount).toLocaleString('fa-IR')} تومان است.`
    };
  }

  const isPercentage =
    found.type === 'percentage' || (Boolean(found.percent) && (found.amount === undefined || found.amount === null || Number(found.amount) === 0));
  const rate = Number(found.amount ?? found.percent ?? 0);
  if (!Number.isFinite(rate) || rate <= 0) {
    return { valid: false, error: 'پیکربندی مبلغ این کد تخفیف نامعتبر است.' };
  }

  let discountAmount = 0;
  if (isPercentage) {
    discountAmount = Math.round((sub * rate) / 100);
    if (found.maxDiscountAmount && Number(found.maxDiscountAmount) > 0 && discountAmount > Number(found.maxDiscountAmount)) {
      discountAmount = Number(found.maxDiscountAmount);
    }
  } else {
    discountAmount = Math.min(rate, sub);
  }
  discountAmount = Math.max(0, Math.min(discountAmount, sub));

  return {
    valid: true,
    discountObj: found,
    code: String(found.code).trim().toUpperCase(),
    discountAmount,
    description: found.description
  };
}

// ============================================================================
// MASS ASSIGNMENT & SCHEMA VALIDATION (OWASP ASVS V5.1, V13.2)
// ============================================================================

export type OrderStatus =
  | 'PENDING_PAYMENT'
  | 'PAID'
  | 'PROCESSING'
  | 'SHIPPED'
  | 'DELIVERED'
  | 'PAYMENT_FAILED'
  | 'CANCELLED'
  | 'CANCELED'
  | 'RETURNED'
  | 'REFUNDED';

// Strict state machine transitions for orders
const ORDER_STATE_TRANSITIONS: Record<OrderStatus, OrderStatus[]> = {
  PENDING_PAYMENT: ['PAID', 'PAYMENT_FAILED', 'CANCELLED', 'CANCELED'],
  PAYMENT_FAILED: ['PENDING_PAYMENT', 'PAID', 'CANCELLED', 'CANCELED'],
  PAID: ['PROCESSING', 'CANCELLED', 'CANCELED', 'REFUNDED'],
  PROCESSING: ['SHIPPED', 'CANCELLED', 'CANCELED'],
  SHIPPED: ['DELIVERED', 'RETURNED'],
  DELIVERED: [], // Terminal state
  CANCELLED: [], // Terminal state
  CANCELED: [],  // Terminal state
  RETURNED: [],  // Terminal state
  REFUNDED: []   // Terminal state
};

export function isTerminalOrderStatus(status: string): boolean {
  return ['DELIVERED', 'CANCELLED', 'CANCELED', 'RETURNED', 'REFUNDED'].includes(status);
}

export function isCancelledOrderStatus(status: string): boolean {
  return status === 'CANCELLED' || status === 'CANCELED';
}

export function isPaidOrFulfilledOrderStatus(status: string): boolean {
  return ['PAID', 'PROCESSING', 'SHIPPED', 'DELIVERED'].includes(status);
}

export function isValidOrderStatus(status: string): status is OrderStatus {
  return [
    'PENDING_PAYMENT',
    'PAID',
    'PROCESSING',
    'SHIPPED',
    'DELIVERED',
    'PAYMENT_FAILED',
    'CANCELLED',
    'CANCELED',
    'RETURNED',
    'REFUNDED'
  ].includes(status);
}

export function isValidOrderStatusTransition(currentStatus: OrderStatus, targetStatus: OrderStatus): boolean {
  if (currentStatus === targetStatus) return true;
  const allowed = ORDER_STATE_TRANSITIONS[currentStatus];
  return Boolean(allowed && allowed.includes(targetStatus));
}

/**
 * Validates and extracts only allowlisted fields for Order creation.
 * Defends against Mass Assignment (CWE-915).
 */
export function sanitizeOrderInput(body: any): {
  customerName: string;
  customerPhone: string;
  customerEmail?: string;
  customerAddress: string;
  province: string;
  city: string;
  postalCode: string;
  customerNotes?: string;
  paymentMethod: 'gateway' | 'card';
  promoCode?: string;
  idempotencyKey?: string;
  items: Array<{
    productId: string;
    selectedVariantId?: string;
    selectedColor?: string;
    selectedSize?: string;
    quantity: number;
    customization?: {
      customFee?: number;
      elements?: any[];
      layers?: any[];
      views?: Record<string, any>;
      mockupView?: string;
      viewName?: string;
      designImageUrl?: string;
      previewMockupUrl?: string;
    };
  }>;
} | { error: string } {
  if (!body || typeof body !== 'object') {
    return { error: 'داده‌های سفارش نامعتبر است.' };
  }

  const customerName = sanitizeText(body.customerName, 80);
  if (!customerName || customerName.length < 2) {
    return { error: 'نام و نام خانوادگی خریدار باید حداقل ۲ کاراکتر باشد.' };
  }

  const customerPhone = normalizeIranianMobile(body.customerPhone);
  if (!customerPhone) {
    return { error: 'شماره موبایل نامعتبر است. لطفاً شماره ۱۱ رقمی معتبر ایرانی (با شروع ۰۹ یا +۹۸) وارد نمایید.' };
  }

  const customerAddress = sanitizeText(body.customerAddress || body.address, 300);
  if (!customerAddress || customerAddress.length < 5) {
    return { error: 'نشانی پستی باید حداقل ۵ کاراکتر باشد.' };
  }

  const province = sanitizeText(body.province || body.customerProvince || 'تهران', 50);
  const city = sanitizeText(body.city || body.customerCity || 'تهران', 50);
  const postalCode = cleanPhoneNumber(body.postalCode || body.customerPostal || '');

  const emailCheck = normalizeAndValidateEmail(body.customerEmail);
  const customerEmail = emailCheck.valid ? emailCheck.value : undefined;
  const customerNotes = body.customerNotes ? sanitizeText(body.customerNotes, 300) : undefined;
  const promoCode = body.promoCode || body.appliedCode ? String(body.promoCode || body.appliedCode).trim().toUpperCase() : undefined;
  const idempotencyKey = typeof body.idempotencyKey === 'string' && body.idempotencyKey.trim()
    ? sanitizeText(body.idempotencyKey.trim(), 100)
    : undefined;

  const paymentMethod =
    body.paymentMethod === 'gateway' ||
    (typeof body.paymentMethod === 'string' && (body.paymentMethod.includes('درگاه') || body.paymentMethod.toLowerCase().includes('zarinpal')))
      ? 'gateway'
      : 'card';

  if (!Array.isArray(body.items) || body.items.length === 0) {
    return { error: 'سبد خرید نمی‌تواند خالی باشد.' };
  }

  if (body.items.length > 50) {
    return { error: 'تعداد اقلام سفارش بیش از حد مجاز (حداکثر ۵۰ قلم) است.' };
  }

  const validatedItems: any[] = [];
  for (const it of body.items) {
    if (!it || typeof it !== 'object') {
      return { error: 'آیتم نامعتبر در سبد خرید.' };
    }
    const productId = sanitizeText(it.productId || it.product?.id || '', 50);
    if (!productId) {
      return { error: 'شناسه محصول الزامی است.' };
    }
    const rawQty = Number(it.quantity);
    if (!Number.isFinite(rawQty) || rawQty < 1 || rawQty > 20 || Math.floor(rawQty) !== rawQty) {
      return { error: 'تعداد هر محصول باید یک عدد صحیح بین ۱ تا ۲۰ عدد باشد.' };
    }
    const quantity = Math.floor(rawQty);

    const selectedVariantId = it.selectedVariantId ? sanitizeText(it.selectedVariantId, 60) : undefined;
    const selectedColor = it.selectedColor ? sanitizeText(it.selectedColor, 40) : undefined;
    const selectedSize = it.selectedSize ? sanitizeText(it.selectedSize, 30) : undefined;

    let customization: any = undefined;
    if (it.customization && typeof it.customization === 'object') {
      // Client customFee is strictly ignored (A1): authoritative fee is computed server-side per product
      customization = {
        elements: Array.isArray(it.customization.elements) ? it.customization.elements.slice(0, 20) : [],
        layers: Array.isArray(it.customization.layers) ? it.customization.layers.slice(0, 20) : undefined,
        views: it.customization.views && typeof it.customization.views === 'object' ? it.customization.views : undefined,
        mockupView: sanitizeText(it.customization.mockupView || '', 30),
        viewName: sanitizeText(it.customization.viewName || '', 40),
        designImageUrl: typeof it.customization.designImageUrl === 'string' ? it.customization.designImageUrl.slice(0, 3000000) : undefined,
        previewMockupUrl: typeof it.customization.previewMockupUrl === 'string' ? it.customization.previewMockupUrl.slice(0, 3000000) : undefined
      };
    }

    validatedItems.push({
      productId,
      selectedVariantId,
      quantity,
      selectedColor,
      selectedSize,
      customization
    });
  }

  return {
    customerName,
    customerPhone,
    customerEmail,
    customerAddress,
    province,
    city,
    postalCode,
    customerNotes,
    paymentMethod,
    promoCode,
    idempotencyKey,
    items: validatedItems
  };
}

function sanitizeSafeAttributesMap(raw: any): Record<string, any> | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const out: Record<string, any> = {};
  let count = 0;
  for (const [k, v] of Object.entries(raw)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
    const cleanKey = sanitizeText(k, 80);
    if (!cleanKey) continue;
    if (typeof v === 'string') {
      out[cleanKey] = sanitizeText(v, 300);
    } else if (typeof v === 'number' && Number.isFinite(v)) {
      out[cleanKey] = v;
    } else if (typeof v === 'boolean') {
      out[cleanKey] = v;
    } else if (Array.isArray(v)) {
      out[cleanKey] = v.slice(0, 20).map((item) =>
        typeof item === 'string' ? sanitizeText(item, 100) : typeof item === 'number' && Number.isFinite(item) ? item : Boolean(item)
      );
    }
    count++;
    if (count >= 50) break;
  }
  return out;
}

/**
 * Whitelist extraction for Category updates (B5).
 */
export function sanitizeCategoryInput(body: any, isNew = false): {
  title?: string;
  slug?: string;
  parentId?: string | null;
  icon?: string;
  image?: string;
  banner?: string;
  description?: string;
  sortOrder?: number;
  active?: boolean;
  showInMainMenu?: boolean;
  showInHome?: boolean;
  showInFooter?: boolean;
  seoTitle?: string;
  seoDescription?: string;
} | { error: string } {
  if (!body || typeof body !== 'object') return { error: 'داده‌های دسته‌بندی نامعتبر است.' };

  const res: any = {};

  if (body.title !== undefined || isNew) {
    const title = sanitizeText(body.title, 80);
    if (!title) return { error: 'عنوان دسته‌بندی الزامی است.' };
    res.title = title;
  }

  if (body.slug !== undefined) {
    res.slug = sanitizeText(body.slug, 80) || undefined;
  }

  if (body.parentId !== undefined) {
    res.parentId = body.parentId ? sanitizeText(body.parentId, 60) : null;
  }

  if (body.icon !== undefined) res.icon = sanitizeText(body.icon, 50) || undefined;
  if (body.image !== undefined) res.image = sanitizeText(body.image, 500) || undefined;
  if (body.banner !== undefined) res.banner = sanitizeText(body.banner, 500) || undefined;
  if (body.description !== undefined) res.description = sanitizeText(body.description, 500) || undefined;
  if (body.sortOrder !== undefined) res.sortOrder = Number.isFinite(Number(body.sortOrder)) ? Number(body.sortOrder) : 0;
  if (body.active !== undefined) res.active = Boolean(body.active);
  if (body.showInMainMenu !== undefined) res.showInMainMenu = Boolean(body.showInMainMenu);
  if (body.showInHome !== undefined) res.showInHome = Boolean(body.showInHome);
  if (body.showInFooter !== undefined) res.showInFooter = Boolean(body.showInFooter);
  if (body.seoTitle !== undefined) res.seoTitle = sanitizeText(body.seoTitle, 160) || undefined;
  if (body.seoDescription !== undefined) res.seoDescription = sanitizeText(body.seoDescription, 320) || undefined;

  return res;
}

/**
 * Whitelist extraction for Product creation and partial/full updates (B5).
 * Covers all fields in Product / AdminProducts.tsx while preventing Mass Assignment
 * and preserving omitted fields (such as variants during inline price/stock edits).
 */
export function sanitizeProductInput(body: any, isNew = false): Record<string, any> | { error: string } {
  if (!body || typeof body !== 'object') return { error: 'داده‌های محصول نامعتبر است.' };

  const res: Record<string, any> = {};

  if (body.name !== undefined || isNew) {
    const name = sanitizeText(body.name, 140);
    if (!name) return { error: 'نام محصول الزامی است.' };
    res.name = name;
  }

  if (body.slug !== undefined) {
    res.slug = sanitizeText(body.slug, 140) || undefined;
  }

  if (body.price !== undefined || isNew) {
    const price = Number(body.price);
    if (!Number.isFinite(price) || price < 0 || price > 500000000) {
      return { error: 'قیمت محصول باید یک عدد معتبر باشد.' };
    }
    res.price = Math.round(price);
  }

  if ('discountPrice' in body) {
    if (body.discountPrice === undefined || body.discountPrice === null || body.discountPrice === '') {
      res.discountPrice = undefined;
    } else {
      const disc = Number(body.discountPrice);
      if (!Number.isFinite(disc) || disc < 0 || disc > 500000000) {
        return { error: 'قیمت تخفیف‌خورده نامعتبر است.' };
      }
      res.discountPrice = Math.round(disc);
    }
  }

  if (body.categoryId !== undefined || isNew) {
    res.categoryId = sanitizeText(body.categoryId || 'general', 60) || 'general';
  }

  if ('relatedCategoryIds' in body) {
    res.relatedCategoryIds = Array.isArray(body.relatedCategoryIds)
      ? body.relatedCategoryIds.slice(0, 20).map((c: any) => sanitizeText(c, 60)).filter(Boolean)
      : undefined;
  }

  if (body.image !== undefined) res.image = sanitizeText(body.image, 500);
  if (Array.isArray(body.images)) {
    res.images = body.images.slice(0, 15).map((u: any) => sanitizeText(u, 500)).filter(Boolean);
  }

  if ('videoUrl' in body) res.videoUrl = body.videoUrl ? sanitizeText(body.videoUrl, 500) : undefined;
  if ('brand' in body) res.brand = body.brand ? sanitizeText(body.brand, 80) : undefined;
  if ('sku' in body) res.sku = body.sku ? sanitizeText(body.sku, 80) : undefined;
  if ('barcode' in body) res.barcode = body.barcode ? sanitizeText(body.barcode, 80) : undefined;
  if (body.description !== undefined) res.description = sanitizeText(body.description, 3000);

  if (body.stock !== undefined || isNew) {
    const stock = Number(body.stock ?? 0);
    res.stock = Number.isFinite(stock) && stock >= 0 ? Math.floor(stock) : 0;
  }

  if (body.status !== undefined) {
    const validStatuses = ['published', 'active', 'inactive', 'draft', 'out_of_stock', 'archived'];
    res.status = validStatuses.includes(body.status) ? body.status : 'active';
  } else if (isNew) {
    res.status = 'active';
  }

  if (body.isFeatured !== undefined) res.isFeatured = Boolean(body.isFeatured);
  if (body.isNewArrival !== undefined) res.isNewArrival = Boolean(body.isNewArrival);
  if (body.isBestSeller !== undefined) res.isBestSeller = Boolean(body.isBestSeller);
  if (body.isOnSale !== undefined) res.isOnSale = Boolean(body.isOnSale);

  if ('weight' in body) {
    if (body.weight === undefined || body.weight === null || body.weight === '') {
      res.weight = undefined;
    } else if (typeof body.weight === 'number' && Number.isFinite(body.weight)) {
      res.weight = body.weight;
    } else {
      res.weight = sanitizeText(String(body.weight), 60);
    }
  }

  if ('dimensions' in body) {
    if (body.dimensions && typeof body.dimensions === 'object') {
      res.dimensions = {
        length: Number.isFinite(Number(body.dimensions.length)) ? Number(body.dimensions.length) : undefined,
        width: Number.isFinite(Number(body.dimensions.width)) ? Number(body.dimensions.width) : undefined,
        height: Number.isFinite(Number(body.dimensions.height)) ? Number(body.dimensions.height) : undefined
      };
    } else {
      res.dimensions = undefined;
    }
  }

  if ('warranty' in body) res.warranty = body.warranty ? sanitizeText(body.warranty, 200) : undefined;
  if ('shippingInfo' in body) res.shippingInfo = body.shippingInfo ? sanitizeText(body.shippingInfo, 300) : undefined;
  if ('returnPolicy' in body) res.returnPolicy = body.returnPolicy ? sanitizeText(body.returnPolicy, 300) : undefined;
  if ('material' in body) res.material = body.material ? sanitizeText(body.material, 120) : undefined;
  if ('fit' in body) res.fit = body.fit ? sanitizeText(body.fit, 120) : undefined;

  if (Array.isArray(body.tags)) {
    res.tags = body.tags.slice(0, 30).map((t: any) => sanitizeText(t, 50)).filter(Boolean);
  }

  if (body.customizable !== undefined) res.customizable = Boolean(body.customizable);
  if (body.allowCustomization !== undefined) res.allowCustomization = Boolean(body.allowCustomization);
  if (body.isCustomizable !== undefined) res.isCustomizable = Boolean(body.isCustomizable);
  if ('customizationFee' in body) {
    if (body.customizationFee === undefined || body.customizationFee === null || body.customizationFee === '') {
      res.customizationFee = undefined;
    } else {
      const fee = Number(body.customizationFee);
      if (!Number.isFinite(fee) || fee < 0 || fee > 5000000) {
        return { error: 'کارمزد طراحی اختصاصی نامعتبر است.' };
      }
      res.customizationFee = Math.round(fee);
    }
  }

  if ('views' in body) {
    if (Array.isArray(body.views)) {
      res.views = body.views
        .slice(0, 8)
        .filter((v: any) => v && typeof v === 'object')
        .map((v: any) => ({
          id: sanitizeText(v.id || `view-${Date.now()}`, 60),
          name: sanitizeText(v.name || 'front', 30),
          title: sanitizeText(v.title || '', 80),
          image: sanitizeText(v.image || '', 500),
          ...(v.printableArea && typeof v.printableArea === 'object'
            ? {
                printableArea: {
                  x: Number(v.printableArea.x) || 0,
                  y: Number(v.printableArea.y) || 0,
                  width: Number(v.printableArea.width) || 40,
                  height: Number(v.printableArea.height) || 40
                }
              }
            : {})
        }));
    } else {
      res.views = undefined;
    }
  }

  if (Array.isArray(body.colors)) {
    res.colors = body.colors
      .slice(0, 20)
      .filter((c: any) => c && typeof c === 'object')
      .map((c: any) => ({
        name: sanitizeText(c.name || '', 50),
        hex: sanitizeText(c.hex || '#111110', 20),
        ...(c.image ? { image: sanitizeText(c.image, 500) } : {})
      }));
  }

  if (Array.isArray(body.sizes)) {
    res.sizes = body.sizes.slice(0, 20).map((s: any) => sanitizeText(String(s), 30)).filter(Boolean);
  }

  if (Array.isArray(body.specifications)) {
    res.specifications = body.specifications
      .slice(0, 40)
      .filter((s: any) => s && typeof s === 'object')
      .map((s: any) => ({
        ...(s.id ? { id: sanitizeText(s.id, 60) } : {}),
        key: sanitizeText(s.key || '', 100),
        value: sanitizeText(s.value || '', 300)
      }))
      .filter((s: any) => s.key || s.value);
  }

  if ('attributes' in body) {
    if (Array.isArray(body.attributes)) {
      res.attributes = body.attributes.slice(0, 30);
    } else {
      res.attributes = sanitizeSafeAttributesMap(body.attributes);
    }
  }

  if ('variants' in body) {
    if (Array.isArray(body.variants)) {
      res.variants = body.variants
        .slice(0, 100)
        .filter((v: any) => v && typeof v === 'object')
        .map((v: any, idx: number) => {
          const vPrice = Number(v.price ?? 0);
          const vDisc =
            v.discountPrice !== undefined && v.discountPrice !== null && v.discountPrice !== ''
              ? Number(v.discountPrice)
              : undefined;
          const vStock = Number(v.stock ?? 0);
          return {
            id: sanitizeText(v.id || `var-${Date.now()}-${idx}`, 60),
            title: sanitizeText(v.title || 'تنوع', 120),
            ...(v.sku ? { sku: sanitizeText(v.sku, 80) } : {}),
            price: Number.isFinite(vPrice) && vPrice >= 0 ? Math.round(vPrice) : 0,
            ...(vDisc !== undefined && Number.isFinite(vDisc) && vDisc >= 0
              ? { discountPrice: Math.round(vDisc) }
              : {}),
            stock: Number.isFinite(vStock) && vStock >= 0 ? Math.floor(vStock) : 0,
            attributes: sanitizeSafeAttributesMap(v.attributes) || {},
            ...(v.image ? { image: sanitizeText(v.image, 500) } : {})
          };
        });
    } else if (body.variants === null || body.variants === undefined) {
      res.variants = undefined;
    }
  }

  if (Array.isArray(body.details)) {
    res.details = body.details.slice(0, 20).map((d: any) => sanitizeText(String(d), 300)).filter(Boolean);
  }

  return res;
}

/**
 * Whitelist extraction for Discount code creation/updates (B5).
 * Blocks tampering with usedCount / usageCount / id or prototype pollution.
 */
export function sanitizeDiscountInput(body: any, isNew = false): Record<string, any> | { error: string } {
  if (!body || typeof body !== 'object') return { error: 'داده‌های کد تخفیف نامعتبر است.' };

  const res: Record<string, any> = {};

  if (body.code !== undefined || isNew) {
    const code = sanitizeText(String(body.code || ''), 40).toUpperCase().replace(/\s+/g, '');
    if (!code) return { error: 'کد تخفیف الزامی است.' };
    res.code = code;
  }

  if (body.type !== undefined) {
    res.type = body.type === 'fixed' ? 'fixed' : 'percentage';
  }

  if (body.percent !== undefined) {
    const pct = Number(body.percent);
    if (!Number.isFinite(pct) || pct < 0 || pct > 100) {
      return { error: 'درصد تخفیف باید عددی بین ۰ تا ۱۰۰ باشد.' };
    }
    res.percent = Math.round(pct);
  }

  if (body.amount !== undefined) {
    const amt = Number(body.amount);
    if (!Number.isFinite(amt) || amt < 0 || amt > 500000000) {
      return { error: 'مبلغ تخفیف نامعتبر است.' };
    }
    res.amount = Math.round(amt);
  }

  if (body.description !== undefined) res.description = sanitizeText(body.description, 300);

  if ('minOrderAmount' in body) {
    const minOrd = Number(body.minOrderAmount || 0);
    res.minOrderAmount = Number.isFinite(minOrd) && minOrd >= 0 ? Math.round(minOrd) : 0;
  }

  if ('maxDiscountAmount' in body) {
    const maxDisc = Number(body.maxDiscountAmount || 0);
    res.maxDiscountAmount = Number.isFinite(maxDisc) && maxDisc > 0 ? Math.round(maxDisc) : undefined;
  }

  if ('maxUses' in body) {
    const maxUses = Number(body.maxUses || 0);
    res.maxUses = Number.isFinite(maxUses) && maxUses > 0 ? Math.floor(maxUses) : undefined;
  }

  if ('usageLimit' in body) {
    const usageLimit = Number(body.usageLimit || 0);
    res.usageLimit = Number.isFinite(usageLimit) && usageLimit > 0 ? Math.floor(usageLimit) : undefined;
  }

  if ('expiryDate' in body) {
    res.expiryDate = body.expiryDate ? sanitizeText(String(body.expiryDate), 60) : undefined;
  }

  if ('expiresAt' in body) {
    res.expiresAt = body.expiresAt ? sanitizeText(String(body.expiresAt), 60) : undefined;
  }

  if (body.active !== undefined) res.active = Boolean(body.active);

  return res;
}
