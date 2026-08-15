function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...headers,
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
  const uniqueSuffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const objectKey = `products/${safeCategory}-${safeId}-${uniqueSuffix}.${extension}`;

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

async function uploadImages(bucket, env, files, categoryId, productId) {
  const uploads = [];
  for (const file of files || []) {
    if (!file || typeof file.arrayBuffer !== 'function') continue;
    uploads.push(await uploadImage(bucket, env, file, categoryId, productId));
  }
  return uploads;
}

async function deleteImageIfNeeded(bucket, previousImageKey, nextImageKey) {
  if (!previousImageKey || !nextImageKey || previousImageKey === nextImageKey) return;
  await bucket.delete(previousImageKey);
}

async function deleteImageKeys(bucket, keys) {
  if (!Array.isArray(keys) || keys.length === 0) return;
  await Promise.all(keys.map((key) => key ? bucket.delete(key) : Promise.resolve()));
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

    const adminHeaderName = String(env.ADMIN_HEADER_NAME || 'X-Admin-Secret');
    const catalogCacheTtl = Number(env.CATALOG_CACHE_TTL || 60);
    const catalogCacheStale = Number(env.CATALOG_CACHE_STALE || 300);

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': `Content-Type, ${adminHeaderName}`,
      'Access-Control-Max-Age': '86400',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (!env.GARMENT_BUCKET) {
      console.error('[worker] GARMENT_BUCKET binding missing');
      return jsonResponse({ success: false, error: 'The GARMENT_BUCKET binding is missing.' }, 500, corsHeaders);
    }

    const bucket = env.GARMENT_BUCKET;
    console.log('[worker] bucket binding available');
    const pathname = normalizeRoute(url.pathname);

    if (request.method === 'GET' && pathname === '/catalog') {
      console.log('[worker] GET /catalog');
      try {
        const cache = caches.default;
        const cacheKey = new Request(request.url, { method: 'GET' });
        const cached = await cache.match(cacheKey);
        if (cached) {
          console.log('[worker] serving catalog from edge cache');
          return cached.clone();
        }

        const products = await readCatalog(bucket);
        console.log('[worker] catalog read result', { count: products.length });

        const headers = {
          ...corsHeaders,
          'content-type': 'application/json; charset=utf-8',
          'Cache-Control': `public, max-age=${catalogCacheTtl}, stale-while-revalidate=${catalogCacheStale}`,
        };

        const resp = new Response(JSON.stringify(products), { status: 200, headers });
        // put into edge cache (await to ensure it's stored)
        await caches.default.put(cacheKey, resp.clone());
        return resp;
      } catch (err) {
        console.error('[worker] error serving catalog', err);
        return jsonResponse([], 200, corsHeaders);
      }
    }

    if (request.method === 'GET' && pathname === '/') {
      console.log('[worker] health check');
      return jsonResponse({ ok: true, message: 'garment-admin-api worker is running.' }, 200, corsHeaders);
    }

    const providedSecret = request.headers.get(adminHeaderName) || '';
    console.log('[worker] auth check', { header: adminHeaderName, providedSecretLength: providedSecret.length, expectedSecretLength: String(env.ADMIN_SECRET_KEY || '').length });
    if (providedSecret !== env.ADMIN_SECRET_KEY) {
      console.warn('[worker] unauthorized request');
      return jsonResponse({ success: false, error: 'Unauthorized' }, 401, corsHeaders);
    }

    if (request.method !== 'POST') {
      return jsonResponse({ success: false, error: 'Method not allowed' }, 405, corsHeaders);
    }

    if (pathname === '/add-product') {
      console.log('[worker] route /add-product');
      const body = await parseBody(request);
      console.log('[worker] parsed body type', body.type);
      if (body.type === 'none') {
        return jsonResponse({ success: false, error: 'Provide JSON or multipart/form-data.' }, 400, corsHeaders);
      }

      const data = body.value;
      const imageFiles = body.type === 'formData'
        ? (data.getAll('images') || []).filter((item) => item && typeof item === 'object' && typeof item.arrayBuffer === 'function')
        : [];
      const legacyFile = body.type === 'formData' ? data.get('image') : null;
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
      const stockBySizeRaw = getBodyValue(data, 'stockBySize') || '';
      let stockBySize = {};
      try {
        const parsed = typeof stockBySizeRaw === 'string' && stockBySizeRaw.trim() ? JSON.parse(stockBySizeRaw) : {};
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          stockBySize = parsed;
        }
      } catch (e) {
        stockBySize = {};
      }
      const normalizedStockBySize = {};
      for (const size of sizes) {
        const rawValue = Number(stockBySize[size]);
        normalizedStockBySize[size] = Number.isFinite(rawValue) && rawValue >= 0 ? Math.floor(rawValue) : 10;
      }
      const specsRaw = getBodyValue(data, 'specs') || '';
      let specs;
      try {
        const parsed = typeof specsRaw === 'string' && specsRaw.trim() ? JSON.parse(specsRaw) : undefined;
        specs = parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : undefined;
      } catch (e) {
        specs = undefined;
      }

      const products = await readCatalog(bucket);
      console.log('[worker] existing catalog count before add', { count: products.length });
      const product = {
        id,
        name,
        category,
        categoryId,
        price,
        description,
        sizes,
        stockBySize: Object.keys(normalizedStockBySize).length > 0 ? normalizedStockBySize : undefined,
        specs: specs && Object.keys(specs).length > 0 ? specs : undefined,
        image: '',
        images: [],
        imageKey: '',
        imageKeys: [],
      };

      const uploads = imageFiles.length > 0 ? await uploadImages(bucket, env, imageFiles, categoryId, id) : [];
      if (legacyFile && typeof legacyFile === 'object' && 'arrayBuffer' in legacyFile && uploads.length === 0) {
        const upload = await uploadImage(bucket, env, legacyFile, categoryId, id);
        uploads.push(upload);
      }

      if (uploads.length > 0) {
        product.image = uploads[0].publicUrl;
        product.images = uploads.map((upload) => upload.publicUrl);
        product.imageKey = uploads[0].objectKey;
        product.imageKeys = uploads.map((upload) => upload.objectKey);
      }

      products.push(product);
      console.log('[worker] writing catalog');
      await writeCatalog(bucket, products);
      console.log('[worker] catalog written successfully');
      return jsonResponse({ success: true, product, products }, 200, corsHeaders);
    }

    if (pathname === '/edit-product') {
      console.log('[worker] route /edit-product');
      const body = await parseBody(request);
      console.log('[worker] parsed edit body type', body.type);
      if (body.type === 'none') {
        return jsonResponse({ success: false, error: 'Provide JSON or multipart/form-data.' }, 400, corsHeaders);
      }

      const data = body.value;
      const imageFiles = body.type === 'formData'
        ? (data.getAll('images') || []).filter((item) => item && typeof item === 'object' && typeof item.arrayBuffer === 'function')
        : [];
      const legacyFile = body.type === 'formData' ? data.get('image') : null;
      const imageKeys = body.type === 'formData'
        ? (data.getAll('imageKeys') || []).filter((item) => typeof item === 'string' && item.trim() !== '')
        : [];
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
      const stockBySizeRaw = getBodyValue(data, 'stockBySize') || '';
      let stockBySize = {};
      try {
        const parsed = typeof stockBySizeRaw === 'string' && stockBySizeRaw.trim() ? JSON.parse(stockBySizeRaw) : {};
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          stockBySize = parsed;
        }
      } catch (e) {
        stockBySize = {};
      }
      const normalizedStockBySize = {};
      for (const size of sizes) {
        const rawValue = Number(stockBySize[size]);
        normalizedStockBySize[size] = Number.isFinite(rawValue) && rawValue >= 0 ? Math.floor(rawValue) : 10;
      }
      const specsRaw = getBodyValue(data, 'specs') || '';
      const existingImageKey = String(getBodyValue(data, 'imageKey') || '').trim();

      const products = await readCatalog(bucket);
      console.log('[worker] existing catalog count before edit', { count: products.length, id });
      const index = products.findIndex((item) => item.id === id);
      let specs = products[index]?.specs;
      try {
        if (typeof specsRaw === 'string' && specsRaw.trim()) {
          const parsed = JSON.parse(specsRaw);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            specs = parsed;
          }
        } else if (specsRaw === undefined || specsRaw === null || specsRaw === '') {
          specs = {};
        }
      } catch (e) {
        specs = products[index]?.specs;
      }
      if (index < 0) {
        return jsonResponse({ success: false, error: 'Product not found' }, 404, corsHeaders);
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
        stockBySize: Object.keys(normalizedStockBySize).length > 0 ? normalizedStockBySize : (products[index].stockBySize || undefined),
        specs: specs && typeof specs === 'object' && Object.keys(specs).length > 0 ? specs : undefined,
      };

      const uploads = imageFiles.length > 0 ? await uploadImages(bucket, env, imageFiles, categoryId, id) : [];
      if (legacyFile && typeof legacyFile === 'object' && 'arrayBuffer' in legacyFile && uploads.length === 0) {
        const upload = await uploadImage(bucket, env, legacyFile, categoryId, id);
        uploads.push(upload);
      }

      if (uploads.length > 0) {
        nextProduct.image = uploads[0].publicUrl;
        nextProduct.images = uploads.map((upload) => upload.publicUrl);
        nextProduct.imageKey = uploads[0].objectKey;
        nextProduct.imageKeys = uploads.map((upload) => upload.objectKey);
        const keysToDelete = Array.isArray(imageKeys)
          ? imageKeys.filter((key) => !nextProduct.imageKeys.includes(key))
          : [];
        await deleteImageKeys(bucket, keysToDelete);
      } else {
        nextProduct.image = products[index].image || '';
        nextProduct.images = Array.isArray(products[index].images) && products[index].images.length > 0
          ? products[index].images
          : (products[index].image ? [products[index].image] : []);
        nextProduct.imageKey = products[index].imageKey || '';
        nextProduct.imageKeys = Array.isArray(products[index].imageKeys)
          ? products[index].imageKeys
          : products[index].imageKey
            ? [products[index].imageKey]
            : [];
      }

      products[index] = nextProduct;
      console.log('[worker] writing catalog after edit');
      await writeCatalog(bucket, products);
      console.log('[worker] catalog written after edit');
      return jsonResponse({ success: true, product: nextProduct, products }, 200, corsHeaders);
    }

    if (pathname === '/delete-product') {
      console.log('[worker] route /delete-product');
      const body = await parseBody(request);
      console.log('[worker] parsed delete body type', body.type);
      if (body.type === 'none') {
        return jsonResponse({ success: false, error: 'Provide JSON or multipart/form-data.' }, 400, corsHeaders);
      }

      const data = body.value;
      const id = String(getBodyValue(data, 'id') || '').trim();
      const products = await readCatalog(bucket);
      console.log('[worker] existing catalog count before delete', { count: products.length, id });
      const productToDelete = products.find((item) => item.id === id);

      if (!productToDelete) {
        return jsonResponse({ success: false, error: 'Product not found' }, 404, corsHeaders);
      }

      const nextProducts = products.filter((item) => item.id !== id);
      console.log('[worker] writing catalog after delete');
      await writeCatalog(bucket, nextProducts);
      console.log('[worker] catalog written after delete');
      const keysToDelete = [
        ...(Array.isArray(productToDelete.imageKeys) ? productToDelete.imageKeys : []),
        ...(productToDelete.imageKey ? [productToDelete.imageKey] : []),
      ];
      await deleteImageKeys(bucket, keysToDelete);
      return jsonResponse({ success: true, product: productToDelete, products: nextProducts }, 200, corsHeaders);
    }

    if (pathname === '/delete-product-image') {
      console.log('[worker] route /delete-product-image');
      const body = await parseBody(request);
      console.log('[worker] parsed delete image body type', body.type);
      if (body.type === 'none') {
        return jsonResponse({ success: false, error: 'Provide JSON or multipart/form-data.' }, 400, corsHeaders);
      }

      const data = body.value;
      const id = String(getBodyValue(data, 'id') || '').trim();
      const imageUrl = String(getBodyValue(data, 'imageUrl') || '').trim();
      const imageKey = String(getBodyValue(data, 'imageKey') || '').trim();

      const products = await readCatalog(bucket);
      const index = products.findIndex((item) => item.id === id);
      if (index < 0) {
        return jsonResponse({ success: false, error: 'Product not found' }, 404, corsHeaders);
      }

      const product = products[index];
      const currentImages = Array.isArray(product.images) ? product.images.slice() : product.image ? [product.image] : [];
      const currentKeys = Array.isArray(product.imageKeys)
        ? product.imageKeys.slice()
        : product.imageKey
          ? [product.imageKey]
          : [];

      let removedKeys = [];
      let nextImages = currentImages.slice();
      let nextKeys = currentKeys.slice();

      if (imageKey) {
        nextKeys = nextKeys.filter((key) => {
          const shouldKeep = key !== imageKey;
          if (!shouldKeep) removedKeys.push(key);
          return shouldKeep;
        });
        const removeIndex = currentKeys.findIndex((key) => key === imageKey);
        if (removeIndex >= 0) {
          nextImages.splice(removeIndex, 1);
        }
      } else if (imageUrl) {
        const removeIndex = nextImages.findIndex((url) => url === imageUrl);
        if (removeIndex >= 0) {
          nextImages.splice(removeIndex, 1);
          if (nextKeys.length > removeIndex) {
            removedKeys.push(nextKeys[removeIndex]);
            nextKeys.splice(removeIndex, 1);
          }
        }
      }

      if (removedKeys.length === 0) {
        return jsonResponse({ success: false, error: 'Image not found' }, 404, corsHeaders);
      }

      await deleteImageKeys(bucket, removedKeys);

      const nextProduct = {
        ...product,
        images: nextImages,
        imageKeys: nextKeys,
        image: nextImages[0] || '',
        imageKey: nextKeys[0] || '',
      };

      products[index] = nextProduct;
      await writeCatalog(bucket, products);
      console.log('[worker] product updated after image delete', { id, removedKeys });
      return jsonResponse({ success: true, product: nextProduct, products }, 200, corsHeaders);
    }

    console.warn('[worker] route not found', { pathname });
    return jsonResponse({ success: false, error: 'Not found' }, 404, corsHeaders);
  },
};
