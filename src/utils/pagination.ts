import type { PaginationOptions, PaginatedResponse } from '../types/index.js';
import { paginationConfig } from './config.js';

// Placeholder for pagination utilities
export function paginate<T>(
  data: T[], 
  options: PaginationOptions = {}
): PaginatedResponse<T> {
  const size = Math.min(
    options.size ?? paginationConfig.defaultPageSize,
    paginationConfig.maxPageSize
  );
  const page = options.page ?? 1;
  
  // Will be fully implemented in the pagination task
  const startIndex = (page - 1) * size;
  const endIndex = startIndex + size;
  const paginatedData = data.slice(startIndex, endIndex);
  
  return {
    data: paginatedData,
    pagination: {
      page,
      size,
      total: data.length,
      hasNext: endIndex < data.length,
      hasPrev: page > 1
    }
  };
}