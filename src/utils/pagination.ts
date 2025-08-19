import type { PaginationOptions, PaginatedResponse } from '../types/index.js';
import { paginationConfig } from './config.js';
import { logger } from './logger.js';

/**
 * Cursor-based pagination item interface
 */
export interface CursorPaginationItem {
  id: string | number;
  createdAt?: Date | string;
  [key: string]: unknown;
}

/**
 * Enhanced offset-based pagination with performance optimizations
 */
export function paginate<T>(
  data: T[], 
  options: PaginationOptions = {}
): PaginatedResponse<T> {
  const size = Math.min(
    options.size ?? paginationConfig.defaultPageSize,
    paginationConfig.maxPageSize
  );
  const page = Math.max(options.page ?? 1, 1); // Ensure page is at least 1
  
  const total = data.length;
  const totalPages = Math.ceil(total / size);
  const startIndex = (page - 1) * size;
  const endIndex = Math.min(startIndex + size, total);
  
  // Performance optimization: avoid creating intermediate arrays for large datasets
  const paginatedData = data.slice(startIndex, endIndex);
  
  logger.debug('Offset pagination applied', {
    page,
    size,
    total,
    totalPages,
    startIndex,
    endIndex,
    resultCount: paginatedData.length
  });
  
  return {
    data: paginatedData,
    pagination: {
      page,
      size,
      total,
      hasNext: page < totalPages,
      hasPrev: page > 1
    }
  };
}

/**
 * Cursor-based pagination for large datasets with better performance
 * Uses stable sorting by ID to ensure consistent pagination
 */
export function paginateWithCursor<T extends CursorPaginationItem>(
  data: T[],
  options: PaginationOptions & { sortBy?: keyof T; sortOrder?: 'asc' | 'desc' } = {}
): PaginatedResponse<T> {
  const size = Math.min(
    options.size ?? paginationConfig.defaultPageSize,
    paginationConfig.maxPageSize
  );
  const { cursor, sortBy = 'id', sortOrder = 'asc' } = options;
  
  // Sort data for consistent cursor pagination
  const sortedData = [...data].sort((a, b) => {
    const aVal = a[sortBy];
    const bVal = b[sortBy];
    
    if (aVal === bVal) return 0;
    
    const comparison = aVal < bVal ? -1 : 1;
    return sortOrder === 'asc' ? comparison : -comparison;
  });
  
  let startIndex = 0;
  let currentCursor: string | undefined;
  
  // Find starting position based on cursor
  if (cursor) {
    try {
      const cursorData = JSON.parse(Buffer.from(cursor, 'base64').toString());
      const cursorValue = cursorData.value;
      
      startIndex = sortedData.findIndex(item => {
        const itemValue = item[sortBy];
        return sortOrder === 'asc' ? itemValue > cursorValue : itemValue < cursorValue;
      });
      
      if (startIndex === -1) {
        startIndex = sortedData.length; // No more items
      }
    } catch (error) {
      logger.warn('Invalid cursor provided, starting from beginning', { cursor, error });
      startIndex = 0;
    }
  }
  
  const endIndex = Math.min(startIndex + size, sortedData.length);
  const paginatedData = sortedData.slice(startIndex, endIndex);
  
  // Generate cursors for next/prev navigation
  let nextCursor: string | undefined;
  let prevCursor: string | undefined;
  
  if (paginatedData.length > 0) {
    // Next cursor: points to the last item in current page
    if (endIndex < sortedData.length && paginatedData.length > 0) {
      const lastItem = paginatedData[paginatedData.length - 1];
      if (lastItem) {
        nextCursor = Buffer.from(JSON.stringify({
          value: lastItem[sortBy],
          direction: 'next'
        })).toString('base64');
      }
    }
    
    // Previous cursor: points to the first item in current page  
    if (startIndex > 0) {
      const firstItem = paginatedData[0];
      const prevItems = sortedData.slice(Math.max(0, startIndex - size), startIndex);
      if (prevItems.length > 0) {
        const prevItem = prevItems[0];
        if (prevItem) {
          prevCursor = Buffer.from(JSON.stringify({
            value: prevItem[sortBy],
            direction: 'prev'
          })).toString('base64');
        }
      }
    }
  }
  
  logger.debug('Cursor pagination applied', {
    cursor,
    size,
    sortBy,
    sortOrder,
    startIndex,
    endIndex,
    resultCount: paginatedData.length,
    hasNext: !!nextCursor,
    hasPrev: !!prevCursor
  });
  
  return {
    data: paginatedData,
    pagination: {
      size,
      hasNext: !!nextCursor,
      hasPrev: !!prevCursor,
      nextCursor,
      prevCursor
    }
  };
}

/**
 * Async cursor pagination for database or API queries
 * Suitable for scenarios where you need to fetch data in chunks
 */
export async function paginateAsync<T extends CursorPaginationItem>(
  fetchFn: (cursor?: string, size?: number) => Promise<T[]>,
  options: PaginationOptions = {}
): Promise<PaginatedResponse<T>> {
  const size = Math.min(
    options.size ?? paginationConfig.defaultPageSize,
    paginationConfig.maxPageSize
  );
  
  try {
    // Fetch one extra item to determine if there's a next page
    const data = await fetchFn(options.cursor, size + 1);
    
    const hasNext = data.length > size;
    const paginatedData = hasNext ? data.slice(0, size) : data;
    
    let nextCursor: string | undefined;
    let prevCursor: string | undefined;
    
    if (hasNext && paginatedData.length > 0) {
      const lastItem = paginatedData[paginatedData.length - 1];
      if (lastItem) {
        nextCursor = Buffer.from(JSON.stringify({
          value: lastItem.id,
          direction: 'next'
        })).toString('base64');
      }
    }
    
    // For previous cursor, we'd need additional context about the dataset
    // This is typically handled by the calling code that tracks navigation state
    
    logger.debug('Async cursor pagination applied', {
      cursor: options.cursor,
      size,
      resultCount: paginatedData.length,
      hasNext,
      hasPrev: false // Would need additional logic to determine
    });
    
    return {
      data: paginatedData,
      pagination: {
        size,
        hasNext,
        hasPrev: false, // Simplified for this implementation
        nextCursor,
        prevCursor
      }
    };
  } catch (error) {
    logger.error('Async pagination failed', error as Error);
    throw error;
  }
}

/**
 * Utility to create pagination metadata for MCP resource responses
 */
export function createResourcePaginationMeta(
  totalItems: number,
  currentPage: number,
  pageSize: number
): {
  total: number;
  page: number;
  pages: number;
  size: number;
  hasNext: boolean;
  hasPrev: boolean;
} {
  const totalPages = Math.ceil(totalItems / pageSize);
  
  return {
    total: totalItems,
    page: currentPage,
    pages: totalPages,
    size: pageSize,
    hasNext: currentPage < totalPages,
    hasPrev: currentPage > 1
  };
}

/**
 * Parse cursor to extract pagination information
 */
export function parseCursor(cursor: string): { value: unknown; direction: 'next' | 'prev' } | null {
  try {
    return JSON.parse(Buffer.from(cursor, 'base64').toString());
  } catch {
    return null;
  }
}

/**
 * Validate pagination options
 */
export function validatePaginationOptions(options: PaginationOptions): {
  isValid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  
  if (options.page !== undefined) {
    if (!Number.isInteger(options.page) || options.page < 1) {
      errors.push('Page must be a positive integer');
    }
  }
  
  if (options.size !== undefined) {
    if (!Number.isInteger(options.size) || options.size < 1) {
      errors.push('Size must be a positive integer');
    }
    if (options.size > paginationConfig.maxPageSize) {
      errors.push(`Size cannot exceed ${paginationConfig.maxPageSize}`);
    }
  }
  
  if (options.cursor !== undefined) {
    if (typeof options.cursor !== 'string' || options.cursor.trim() === '') {
      errors.push('Cursor must be a non-empty string');
    } else if (!parseCursor(options.cursor)) {
      errors.push('Cursor format is invalid');
    }
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}