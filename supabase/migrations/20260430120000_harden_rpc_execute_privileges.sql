-- Harden RPC execute privileges based on current app usage map.
-- Keep authenticated access for RPCs invoked by frontend/backend app code.
-- Revoke anon/public from business-sensitive RPCs.
-- Revoke authenticated from internal helper/trigger-only functions.

BEGIN;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM anon;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM public;

DO $$
DECLARE
  fn_name text;
  fn_sig text;
BEGIN
  FOREACH fn_name IN ARRAY ARRAY[
    'admin_edit_approved_delivery_challan',
    'allocate_import_costs_to_batches',
    'auto_create_followup',
    'auto_match_smart',
    'create_fund_transfer_with_posting',
    'dismiss_system_task',
    'edit_delivery_challan',
    'fn_cancel_sales_order',
    'fn_release_reservation_by_so_id',
    'fn_reserve_stock_for_so_v2',
    'generate_journal_entry_number',
    'generate_voucher_number',
    'get_cogs_for_period',
    'get_current_financial_year',
    'get_customer_outstanding_summary',
    'get_customer_sales_report',
    'get_expense_vs_profit_report',
    'get_invoice_latest_payment_date',
    'get_invoice_paid_amount',
    'get_invoices_with_balance',
    'get_monthly_sales_report',
    'get_overdue_balances',
    'get_pending_dc_items_for_customer',
    'get_petty_cash_balance_by_date',
    'get_product_performance_report',
    'get_sales_member_performance',
    'get_sales_profit_drilldown',
    'get_sales_profit_summary',
    'get_supplier_outstanding_summary',
    'get_system_tasks_summary',
    'get_trial_balance',
    'mark_requirement_sent',
    'preview_bank_statement_delete',
    'safe_delete_bank_statement_lines',
    'update_sales_invoice_atomic',
    'update_so_delivered_quantity_atomic',
    'adjust_batch_stock_atomic'
  ]
  LOOP
    FOR fn_sig IN
      SELECT p.oid::regprocedure::text
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.proname = fn_name
    LOOP
      EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO authenticated', fn_sig);
    END LOOP;
  END LOOP;
END $$;

-- Internal helper/trigger-oriented functions should not be directly callable from app clients.
DO $$
DECLARE
  fn_name text;
  fn_sig text;
BEGIN
  FOREACH fn_name IN ARRAY ARRAY[
    'post_inventory_movement',
    'next_journal_entry_number',
    'get_expense_account_id',
    'auto_post_expense_accounting'
  ]
  LOOP
    FOR fn_sig IN
      SELECT p.oid::regprocedure::text
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.proname = fn_name
    LOOP
      EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM authenticated', fn_sig);
    END LOOP;
  END LOOP;
END $$;

COMMIT;
