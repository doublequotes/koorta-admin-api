const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Secret',
  'Access-Control-Max-Age': '86400',
};

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...corsHeaders,
    },
  });
}

function sanitizeName(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function normalizeRoute(pathname) {
  const cleaned = String(pathname || '').replace(/\/+$/, '') || '/';
  if (cleaned === '/api') return '/';
  if (cleaned.startsWith('/api/')) return cleaned.slice('/api'.length) || '/';
  return cleaned;
}

async function parseBody(request) {
  const contentType = request.headers.get('content-type') || '';

  if (contentType.includes('application/json')) {
    try {
      return { type: 'json', value: await request.json() };
    } catch {
      return { type: 'json', value: {} };
    }
  }

  if (contentType.includes('multipart/form-data') || contentType.includes('application/x-www-form-urlencoded')) {
    return { type: 'formData', value: await request.formData() };
  }

  return { type: 'none', value: {} };
}

function getBodyValue(data, key) {
  if (data instanceof FormData) return data.get(key);
  if (data && typeof data === 'object') return data[key];
  return '';
}

async function readCatalog(bucket) {
  const object = await bucket.get('product.json');
  if (!object) return [];

  const content = await object.text();
  if (!content) return [];

  try {
    const parsed = JSON.parse(content);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeCatalog(bucket, products) {
  await bucket.put('product.json', JSON.stringify(products, null, 2), {
    cacheControl: 'public, max-age=31536000, immutable',
  });
  return products;
}

async function uploadImage(bucket, env, file, categoryId, productId) {
  const name = file?.name || 'image';
  const extension = (name.split('.').pop() || 'jpg').toLowerCase();
  const safeCategory = sanitizeName(categoryId) || 'product';
  const safeId = sanitizeName(productId) || 'item';
  const objectKey = `products/${safeCategory}-${safeId}.${extension}`;

  const arrayBuffer = await file.arrayBuffer();
  await bucket.put(objectKey, arrayBuffer, {
    httpMetadata: {
      contentType: file.type || 'application/octet-stream',
    },
    cacheControl: 'public, max-age=31536000, immutable',
  });

  const baseValue = env.R2_PUBLIC_BASE_URL || env.PUBLIC_BASE_URL || '';
  const base = String(baseValue).replace(/\/$/, '');

  return {
    objectKey,
    publicUrl: base ? `${base}/${objectKey.replace(/^\/+/, '')}` : objectKey,
  };
}

async function deleteImageIfNeeded(bucket, previousImageKey, nextImageKey) {
  if (!previousImageKey || !nextImageKey || previousImageKey === nextImageKey) return;
  await bucket.delete(previousImageKey);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    console.log('[worker] request received', {
      method: request.method,
      pathname: url.pathname,
      host: url.host,
      headers: Object.fromEntries(request.headers.entries()),
    });

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (!env.GARMENT_BUCKET) {
      console.error('[worker] GARMENT_BUCKET binding missing');
      return jsonResponse({ success: false, error: 'The GARMENT_BUCKET binding is missing.' }, 500);
    }

    const bucket = env.GARMENT_BUCKET;
    console.log('[worker] bucket binding available');
    const pathname = normalizeRoute(url.pathname);

    if (request.method === 'GET' && pathname === '/catalog') {
      console.log('[worker] GET /catalog');
      const products = await readCatalog(bucket);
      console.log('[worker] catalog read result', { count: products.length });
      return jsonResponse(products, 200);
    }

    if (request.method === 'GET' && pathname === '/') {
      console.log('[worker] health check');
      return jsonResponse({ ok: true, message: 'garment-admin-api worker is running.' }, 200);
    }

    const providedSecret = request.headers.get('X-Admin-Secret') || '';
    console.log('[worker] auth check', { providedSecretLength: providedSecret.length, expectedSecretLength: String(env.ADMIN_SECRET_KEY || '').length });
    if (providedSecret !== env.ADMIN_SECRET_KEY) {
      console.warn('[worker] unauthorized request');
      return jsonResponse({ success: false, error: 'Unauthorized' }, 401);
    }

    if (request.method !== 'POST') {
      return jsonResponse({ success: false, error: 'Method not allowed' }, 405);
    }

    if (pathname === '/add-product') {
      console.log('[worker] route /add-product');
      const body = await parseBody(request);
      console.log('[worker] parsed body type', body.type);
      if (body.type === 'none') {
        return jsonResponse({ success: false, error: 'Provide JSON or multipart/form-data.' }, 400);
      }

      const data = body.value;
      const file = body.type === 'formData' ? data.get('image') : null;
      const id = String(getBodyValue(data, 'id') || '').trim();
      const name = String(getBodyValue(data, 'name') || '').trim();
      const category = String(getBodyValue(data, 'category') || '').trim();
      const categoryId = String(getBodyValue(data, 'categoryId') || '').trim();
      const description = String(getBodyValue(data, 'description') || '').trim();
      const price = Number(getBodyValue(data, 'price') || 0);
      const sizes = String(getBodyValue(data, 'sizes') || '')
        .split(',')
        .map((size) => size.trim())
        .filter(Boolean);

      const products = await readCatalog(bucket);
      console.log('[worker] existing catalog count before add', { count: products.length });
      const product = { id, name, category, categoryId, price, description, sizes, image: '', imageKey: '' };

      if (file && typeof file === 'object' && 'arrayBuffer' in file) {
        const upload = await uploadImage(bucket, env, file, categoryId, id);
        product.image = upload.publicUrl;
        product.imageKey = upload.objectKey;
      }

      products.push(product);
      console.log('[worker] writing catalog');
      await writeCatalog(bucket, products);
      console.log('[worker] catalog written successfully');
      return jsonResponse({ success: true, product, products });
    }

    if (pathname === '/edit-product') {
      console.log('[worker] route /edit-product');
      const body = await parseBody(request);
      console.log('[worker] parsed edit body type', body.type);
      if (body.type === 'none') {
        return jsonResponse({ success: false, error: 'Provide JSON or multipart/form-data.' }, 400);
      }

      const data = body.value;
      const file = body.type === 'formData' ? data.get('image') : null;
      const id = String(getBodyValue(data, 'id') || '').trim();
      const name = String(getBodyValue(data, 'name') || '').trim();
      const category = String(getBodyValue(data, 'category') || '').trim();
      const categoryId = String(getBodyValue(data, 'categoryId') || '').trim();
      const description = String(getBodyValue(data, 'description') || '').trim();
      const price = Number(getBodyValue(data, 'price') || 0);
      const sizes = String(getBodyValue(data, 'sizes') || '')
        .split(',')
        .map((size) => size.trim())
        .filter(Boolean);
      const existingImageKey = String(getBodyValue(data, 'imageKey') || '').trim();

      const products = await readCatalog(bucket);
      console.log('[worker] existing catalog count before edit', { count: products.length, id });
      const index = products.findIndex((item) => item.id === id);
      if (index < 0) {
        return jsonResponse({ success: false, error: 'Product not found' }, 404);
      }

      const nextProduct = {
        ...products[index],
        id,
        name,
        category,
        categoryId,
        price,
        description,
        sizes,
      };

      if (file && typeof file === 'object' && 'arrayBuffer' in file) {
        const upload = await uploadImage(bucket, env, file, categoryId, id);
        nextProduct.image = upload.publicUrl;
        nextProduct.imageKey = upload.objectKey;
        await deleteImageIfNeeded(bucket, existingImageKey, upload.objectKey);
      } else {
        nextProduct.image = products[index].image || '';
        nextProduct.imageKey = products[index].imageKey || '';
      }

      products[index] = nextProduct;
      console.log('[worker] writing catalog after edit');
      await writeCatalog(bucket, products);
      console.log('[worker] catalog written after edit');
      return jsonResponse({ success: true, product: nextProduct, products });
    }

    if (pathname === '/delete-product') {
      console.log('[worker] route /delete-product');
      const body = await parseBody(request);
      console.log('[worker] parsed delete body type', body.type);
      if (body.type === 'none') {
        return jsonResponse({ success: false, error: 'Provide JSON or multipart/form-data.' }, 400);
      }

      const data = body.value;
      const id = String(getBodyValue(data, 'id') || '').trim();
      const products = await readCatalog(bucket);
      console.log('[worker] existing catalog count before delete', { count: products.length, id });
      const productToDelete = products.find((item) => item.id === id);

      if (!productToDelete) {
        return jsonResponse({ success: false, error: 'Product not found' }, 404);
      }

      const nextProducts = products.filter((item) => item.id !== id);
      console.log('[worker] writing catalog after delete');
      await writeCatalog(bucket, nextProducts);
      console.log('[worker] catalog written after delete');
      await deleteImageIfNeeded(bucket, productToDelete.imageKey, '');
      return jsonResponse({ success: true, product: productToDelete, products: nextProducts });
    }

    console.warn('[worker] route not found', { pathname });
    return jsonResponse({ success: false, error: 'Not found' }, 404);
  },
};
