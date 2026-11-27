package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/kyverno/policy-reporter/pkg/helper"
	"github.com/kyverno/policy-reporter/pkg/openreports"
	"github.com/kyverno/policy-reporter/pkg/report"
)

type Type = string

const (
	MySQL      Type = "mysql"
	MariaDB    Type = "mariadb"
	PostgreSQL Type = "postgres"
	SQLite     Type = "sqlite"
)

type Store struct {
	db      *bun.DB
	version string
}

///////////////////////////////
///		V1 API Queries		///
///////////////////////////////

func (s *Store) FetchPolicyReports(ctx context.Context, filter Filter, pagination Pagination) ([]PolicyReport, error) {
	list := make([]PolicyReport, 0)

	err := FromQuery(s.db.NewSelect().Model(&list)).
		FilterMap(map[string][]string{
			"pr.source":    filter.Sources,
			"pr.namespace": filter.Namespaces,
		}).
		FilterLabels(filter.ReportLabel).
		FilterValue("pr.type", report.PolicyReportType).
		Pagination(pagination).
		Scan(ctx)

	return list, err
}

func (s *Store) CountPolicyReports(ctx context.Context, filter Filter) (int, error) {
	return CountResult(FromQuery(s.db.NewSelect().Model((*PolicyReport)(nil))).
		FilterMap(map[string][]string{
			"pr.source":    filter.Sources,
			"pr.namespace": filter.Namespaces,
		}).
		FilterLabels(filter.ReportLabel).
		FilterValue("pr.type", report.PolicyReportType).
		GetQuery().
		Count(ctx))
}

func (s *Store) FetchClusterPolicyReports(ctx context.Context, filter Filter, pagination Pagination) ([]PolicyReport, error) {
	list := make([]PolicyReport, 0)

	err := FromQuery(s.db.NewSelect().Model(&list)).
		FilterMap(map[string][]string{
			"pr.source": filter.Sources,
		}).
		FilterLabels(filter.ReportLabel).
		FilterValue("pr.type", report.ClusterPolicyReportType).
		Pagination(pagination).
		Scan(ctx)

	return list, err
}

func (s *Store) CountClusterPolicyReports(ctx context.Context, filter Filter) (int, error) {
	return CountResult(FromQuery(s.db.NewSelect().Model((*PolicyReport)(nil))).
		FilterMap(map[string][]string{
			"pr.source": filter.Sources,
		}).
		FilterLabels(filter.ReportLabel).
		FilterValue("pr.type", report.ClusterPolicyReportType).
		GetQuery().
		Count(ctx))
}

func (s *Store) FetchRuleStatusCounts(ctx context.Context, policy, rule string) ([]StatusCount, error) {
	counts := make([]StatusCount, 0)

	err := s.db.NewSelect().
		Table("policy_report_result").
		ColumnExpr("COUNT(id) as count, result as status").
		Where("rule = ?", rule).
		Where("policy = ?", policy).
		Group("status").
		Scan(ctx, &counts)

	return counts, err
}

func (s *Store) FetchNamespaces(ctx context.Context, filter Filter) ([]string, error) {
	return s.FetchNamespacedFilter(ctx, "resource_namespace", filter)
}

func (s *Store) FetchNamespacedFilter(ctx context.Context, column string, filter Filter) ([]string, error) {
	list := make([]string, 0)

	err := NewFilterQuery(s.db, "f."+column).
		FilterMap(map[string][]string{
			"f.result":             filter.Status,
			"f.source":             filter.Sources,
			"f.category":           filter.Categories,
			"f.policy":             filter.Policies,
			"f.resource_kind":      filter.Kinds,
			"f.resource_api":       filter.ResourceAPIs,
			"f.resource_namespace": filter.Namespaces,
		}).
		FilterReportLabels(filter.ReportLabel).
		NamespaceScope().
		Scan(ctx, &list)

	return list, err
}

func (s *Store) FetchClusterFilter(ctx context.Context, column string, filter Filter) ([]string, error) {
	list := make([]string, 0)

	err := NewFilterQuery(s.db, "f."+column).
		FilterMap(map[string][]string{
			"f.source":        filter.Sources,
			"f.category":      filter.Categories,
			"f.policy":        filter.Policies,
			"f.resource_kind": filter.Kinds,
			"f.resource_api":  filter.ResourceAPIs,
		}).
		FilterReportLabels(filter.ReportLabel).
		ClusterScope().
		Scan(ctx, &list)

	return list, err
}

func (s *Store) FetchNamespacedResources(ctx context.Context, filter Filter) ([]ResourceResult, error) {
	list := make([]ResourceResult, 0)

	err := FromQuery(s.db.NewSelect().Model(&list).Distinct()).
		Columns("resource_name", "resource_kind", "resource_namespace").
		FilterMap(map[string][]string{
			"res.source":             filter.Sources,
			"res.category":           filter.Categories,
			"res.policy":             filter.Policies,
			"res.resource_kind":      filter.Kinds,
			"res.resource_api":       filter.ResourceAPIs,
			"res.resource_namespace": filter.Namespaces,
		}).
		FilterReportLabels(filter.ReportLabel).
		NamespaceScope().
		Scan(ctx, &list)

	return list, err
}

func (s *Store) FetchClusterResources(ctx context.Context, filter Filter) ([]ResourceResult, error) {
	list := make([]ResourceResult, 0)

	err := FromQuery(s.db.NewSelect().Model(&list).Distinct()).
		Columns("resource_name", "resource_kind").
		FilterMap(map[string][]string{
			"f.source":             filter.Sources,
			"f.category":           filter.Categories,
			"f.policy":             filter.Policies,
			"f.resource_kind":      filter.Kinds,
			"f.resource_api":       filter.ResourceAPIs,
			"f.resource_namespace": filter.Namespaces,
		}).
		FilterReportLabels(filter.ReportLabel).
		ClusterScope().
		Scan(ctx, &list)

	return list, err
}

func (s *Store) FetchClusterScopedStatusCounts(ctx context.Context, filter Filter) ([]StatusCount, error) {
	list := make([]StatusCount, 0)

	err := FromQuery(s.db.NewSelect().Model(&list).ColumnExpr("SUM(f.count) as count, f.result as status")).
		FilterMap(map[string][]string{
			"f.source":        filter.Sources,
			"f.category":      filter.Categories,
			"f.policy":        filter.Policies,
			"f.resource_kind": filter.Kinds,
			"f.resource_api":  filter.ResourceAPIs,
			"f.result":        filter.Status,
			"f.severity":      filter.Severities,
		}).
		FilterReportLabels(filter.ReportLabel).
		ClusterScope().
		Group("status").
		Scan(ctx)

	return list, err
}

func (s *Store) FetchNamespaceScopedStatusCounts(ctx context.Context, filter Filter) ([]StatusCount, error) {
	list := make([]StatusCount, 0)

	err := FromQuery(s.db.NewSelect().Model(&list).ColumnExpr("SUM(f.count) as count, f.result as status, f.resource_namespace")).
		FilterMap(map[string][]string{
			"f.source":             filter.Sources,
			"f.category":           filter.Categories,
			"f.policy":             filter.Policies,
			"f.resource_kind":      filter.Kinds,
			"f.resource_api":       filter.ResourceAPIs,
			"f.resource_namespace": filter.Namespaces,
			"f.result":             filter.Status,
			"f.severity":           filter.Severities,
		}).
		FilterReportLabels(filter.ReportLabel).
		NamespaceScope().
		Group("status", "f.resource_namespace").
		Scan(ctx)

	return list, err
}

///////////////////////////////
///		V2 API Queries		///
///////////////////////////////

func (s *Store) FetchSources(ctx context.Context, filter Filter) ([]string, error) {
	list := make([]string, 0)

	err := NewFilterQuery(s.db, "f.source").
		FilterMap(map[string][]string{
			"f.resource_kind": filter.Kinds,
			"f.resource_api":  filter.ResourceAPIs,
		}).
		FilterValue("id", filter.ResourceID).
		FilterReportLabels(filter.ReportLabel).
		Scan(ctx, &list)

	return list, err
}

func (s *Store) FetchCategories(ctx context.Context, filter Filter) ([]Category, error) {
	list := make([]Category, 0)

	err := FromQuery(s.db.NewSelect().Model(&list).ColumnExpr("SUM(f.count) as count")).
		Columns("f.source", "f.category", "f.result", "f.severity").
		FilterMap(map[string][]string{
			"f.source":             filter.Sources,
			"f.category":           filter.Categories,
			"f.resource_kind":      filter.Kinds,
			"f.resource_api":       filter.ResourceAPIs,
			"f.resource_namespace": filter.Namespaces,
		}).
		Exclude(filter, "f").
		FilterReportLabels(filter.ReportLabel).
		Group("f.source", "f.category", "f.result", "f.severity").
		Order("f.source ASC", "f.category ASC").
		Scan(ctx, &list)

	return list, err
}

func (s *Store) FetchResource(ctx context.Context, id string) (ResourceResult, error) {
	result := ResourceResult{}

	err := FromQuery(s.db.NewSelect().Model(&result)).
		Columns("res.id", "resource_uid", "resource_kind", "resource_api_version", "resource_namespace", "resource_name", "res.source", "res.category").
		SelectStatusSummaries().
		FilterValue("res.id", id).
		Group("res.id", "resource_uid", "resource_kind", "resource_api_version", "resource_namespace", "resource_name", "res.source", "res.category").
		GetQuery().
		Limit(1).
		Scan(ctx)

	return result, err
}

func (s *Store) FetchResourceCategories(ctx context.Context, resource string, filter Filter) ([]ResourceCategory, error) {
	list := make([]ResourceCategory, 0)

	err := FromQuery(s.db.NewSelect().Model(&list)).
		Columns("res.source", "res.category").
		SelectStatusSummaries().
		FilterMap(map[string][]string{
			"res.source":   filter.Sources,
			"res.category": filter.Categories,
		}).
		Exclude(filter, "res").
		FilterValue("id", resource).
		FilterReportLabels(filter.ReportLabel).
		Group("res.source", "res.category").
		Order("res.source ASC", "res.category ASC").
		Scan(ctx, &list)

	return list, err
}

func (s *Store) FetchProperty(ctx context.Context, property string, filter Filter) ([]ResultProperty, error) {
	result := make([]ResultProperty, 0)

	err := FromQuery(
		s.db.NewSelect().
			Model(&result).
			Distinct().
			ColumnExpr(fmt.Sprintf("resource_namespace, properties->>'%s' as property", property))).
		FilterMap(map[string][]string{
			"category":           filter.Categories,
			"source":             filter.Sources,
			"policy":             filter.Policies,
			"rules":              filter.Rules,
			"status":             filter.Status,
			"resource_namespace": filter.Namespaces,
		}).
		GetQuery().
		Where(fmt.Sprintf("properties->'%s' IS NOT NULL", property)).
		Scan(ctx)

	return result, err
}

func (s *Store) FetchResourceStatusCounts(ctx context.Context, id string, filter Filter) ([]ResourceStatusCount, error) {
	result := []ResourceStatusCount{}

	err := FromQuery(s.db.NewSelect().Model(&result)).
		Columns("res.source").
		SelectStatusSummaries().
		FilterMap(map[string][]string{
			"res.category": filter.Categories,
			"res.source":   filter.Sources,
			"policy":       filter.Policies,
		}).
		HasStatusResults(filter.Status).
		FilterValue("res.id", id).
		FilterReportLabels(filter.ReportLabel).
		Group("res.source").
		Scan(ctx)

	return result, err
}

func (s *Store) FetchResourceSeverityCounts(ctx context.Context, id string, filter Filter) ([]ResourceSeverityCount, error) {
	result := []ResourceSeverityCount{}

	err := FromQuery(s.db.NewSelect().Model(&result)).
		Columns("res.source").
		SelectSeveritySummaries().
		FilterMap(map[string][]string{
			"res.category": filter.Categories,
			"res.source":   filter.Sources,
			"policy":       filter.Policies,
		}).
		HasSeverityResults(filter.Severities).
		FilterValue("res.id", id).
		FilterReportLabels(filter.ReportLabel).
		Group("res.source").
		Scan(ctx)

	return result, err
}

func (s *Store) FetchNamespaceResourceResults(ctx context.Context, filter Filter, pagination Pagination) ([]ResourceResult, error) {
	results := make([]ResourceResult, 0)

	err := FromQuery(s.db.NewSelect().Model(&results)).
		Columns("res.id", "resource_uid", "resource_kind", "resource_api_version", "resource_namespace", "resource_name").
		SelectStatusSummaries().
		SelectSeveritySummaries().
		Group("res.id", "resource_uid", "resource_kind", "resource_api_version", "resource_namespace", "resource_name", "resource_api").
		FilterMap(map[string][]string{
			"source":             filter.Sources,
			"category":           filter.Categories,
			"resource_namespace": filter.Namespaces,
			"resource_kind":      filter.Kinds,
			"resource_api":       filter.ResourceAPIs,
		}).
		HasStatusResults(filter.Status).
		HasSeverityResults(filter.Severities).
		FilterValue("res.id", filter.ResourceID).
		ResourceSearch(filter.Search).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "res").
		NamespaceScope().
		Pagination(pagination).
		Scan(ctx)

	return results, err
}

func (s *Store) CountNamespaceResourceResults(ctx context.Context, filter Filter) (int, error) {
	return CountResult(FromQuery(s.db.NewSelect().Model((*ResourceResult)(nil))).
		Columns("res.id").
		Distinct().
		FilterMap(map[string][]string{
			"source":             filter.Sources,
			"category":           filter.Categories,
			"resource_namespace": filter.Namespaces,
			"resource_kind":      filter.Kinds,
			"resource_api":       filter.ResourceAPIs,
		}).
		HasStatusResults(filter.Status).
		HasSeverityResults(filter.Severities).
		FilterValue("res.id", filter.ResourceID).
		ResourceSearch(filter.Search).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "res").
		NamespaceScope().
		GetQuery().
		Count(ctx))
}

func (s *Store) FetchTotalResourceResults(ctx context.Context, filter Filter, pagination Pagination) ([]ResourceResult, error) {
	results := make([]ResourceResult, 0)

	err := FromQuery(s.db.NewSelect().Model(&results)).
		Columns("resource_namespace").
		SelectStatusSummaries().
		SelectSeveritySummaries().
		Group("resource_namespace").
		FilterMap(map[string][]string{
			"source":        filter.Sources,
			"category":      filter.Categories,
			"resource_kind": filter.Kinds,
			"resource_api":  filter.ResourceAPIs,
		}).
		HasStatusResults(filter.Status).
		HasSeverityResults(filter.Severities).
		ResourceSearch(filter.Search).
		Exclude(filter, "res").
		Pagination(pagination).
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	return helper.Map(results, func(r ResourceResult) ResourceResult {
		if r.Resource.Namespace != "" {
			r.Resource = Resource{
				Namespace: "",
				Name:      r.Resource.Namespace,
			}
		} else {
			r.Resource = Resource{
				Name: "Cluster Scoped",
			}
		}

		return r
	}), nil
}

func (s *Store) CountTotalResourceResults(ctx context.Context, filter Filter) (int, error) {
	return CountResult(FromQuery(s.db.NewSelect().Model((*ResourceResult)(nil))).
		Columns("resource_namespace").
		Distinct().
		FilterMap(map[string][]string{
			"source":        filter.Sources,
			"category":      filter.Categories,
			"resource_kind": filter.Kinds,
			"resource_api":  filter.ResourceAPIs,
		}).
		HasStatusResults(filter.Status).
		HasSeverityResults(filter.Severities).
		ResourceSearch(filter.Search).
		Exclude(filter, "res").
		GetQuery().
		Count(ctx))
}

func (s *Store) FetchClusterResourceResults(ctx context.Context, filter Filter, pagination Pagination) ([]ResourceResult, error) {
	results := make([]ResourceResult, 0)

	err := FromQuery(s.db.NewSelect().Model(&results)).
		Columns("res.id", "resource_uid", "resource_kind", "resource_api_version", "resource_name", "resource_api").
		SelectStatusSummaries().
		SelectSeveritySummaries().
		Group("res.id", "resource_uid", "resource_kind", "resource_api_version", "resource_name", "resource_api").
		FilterMap(map[string][]string{
			"source":        filter.Sources,
			"category":      filter.Categories,
			"resource_kind": filter.Kinds,
			"resource_api":  filter.ResourceAPIs,
		}).
		HasStatusResults(filter.Status).
		HasSeverityResults(filter.Severities).
		FilterValue("res.id", filter.ResourceID).
		ResourceSearch(filter.Search).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "res").
		ClusterScope().
		Pagination(pagination).
		Scan(ctx)

	return results, err
}

func (s *Store) CountClusterResourceResults(ctx context.Context, filter Filter) (int, error) {
	return CountResult(FromQuery(s.db.NewSelect().Model((*ResourceResult)(nil))).
		Columns("res.id").
		Distinct().
		FilterMap(map[string][]string{
			"source":        filter.Sources,
			"category":      filter.Categories,
			"resource_kind": filter.Kinds,
			"resource_api":  filter.ResourceAPIs,
		}).
		HasStatusResults(filter.Status).
		HasSeverityResults(filter.Severities).
		FilterValue("res.id", filter.ResourceID).
		ResourceSearch(filter.Search).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "res").
		ClusterScope().
		GetQuery().
		Count(ctx))
}

func (s *Store) FetchResourceResults(ctx context.Context, id string, filter Filter) ([]ResourceResult, error) {
	results := make([]ResourceResult, 0)

	err := FromQuery(s.db.NewSelect().Model(&results)).
		Columns("res.id", "resource_uid", "resource_kind", "resource_api_version", "resource_namespace", "resource_name", "res.source", "resource_api").
		SelectStatusSummaries().
		FilterValue(`res.id`, id).
		FilterMap(map[string][]string{
			"source":        filter.Sources,
			"category":      filter.Categories,
			"resource_kind": filter.Kinds,
			"resource_api":  filter.ResourceAPIs,
		}).
		HasStatusResults(filter.Status).
		HasSeverityResults(filter.Severities).
		FilterReportLabels(filter.ReportLabel).
		ResourceSearch(filter.Search).
		Order("res.source ASC").
		Group("res.id", "resource_uid", "resource_kind", "resource_api_version", "resource_namespace", "resource_name", "res.source", "resource_api").
		Scan(ctx)

	return results, err
}

func (s *Store) FetchResourcePolicyResults(ctx context.Context, id string, filter Filter, pagination Pagination) ([]PolicyReportResult, error) {
	results := make([]PolicyReportResult, 0)

	err := FromQuery(s.db.NewSelect().Model(&results)).
		FilterValue(`r.resource_id`, id).
		FilterMap(map[string][]string{
			"source":   filter.Sources,
			"category": filter.Categories,
		}).
		ResultSearch(filter.Search).
		FilterReportLabels(filter.ReportLabel).
		Pagination(pagination).
		Scan(ctx)

	return results, err
}

func (s *Store) CountResourcePolicyResults(ctx context.Context, id string, filter Filter) (int, error) {
	return CountResult(FromQuery(s.db.NewSelect().Model((*PolicyReportResult)(nil))).
		FilterValue(`r.resource_id`, id).
		FilterMap(map[string][]string{
			"source":   filter.Sources,
			"category": filter.Categories,
		}).
		ResultSearch(filter.Search).
		FilterReportLabels(filter.ReportLabel).
		GetQuery().
		Count(ctx))
}

func (s *Store) FetchResults(ctx context.Context, namespaced bool, filter Filter, pagination Pagination) ([]PolicyReportResult, error) {
	results := make([]PolicyReportResult, 0)

	err := FromQuery(s.db.NewSelect().Model(&results)).
		FilterMap(map[string][]string{
			"source":             filter.Sources,
			"category":           filter.Categories,
			"policy":             filter.Policies,
			"rule":               filter.Rules,
			"resource_namespace": filter.Namespaces,
			"resource_kind":      filter.Kinds,
			"resource_api":       filter.ResourceAPIs,
			"resource_name":      filter.Resources,
			"result":             filter.Status,
			"severity":           filter.Severities,
		}).
		Scoped(namespaced).
		FilterValue(`r.resource_id`, filter.ResourceID).
		ResultSearch(filter.Search).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "r").
		Pagination(pagination).
		Scan(ctx)

	return results, err
}

func (s *Store) CountResults(ctx context.Context, namespaced bool, filter Filter) (int, error) {
	return CountResult(FromQuery(s.db.NewSelect().Model((*PolicyReportResult)(nil))).
		FilterMap(map[string][]string{
			"source":             filter.Sources,
			"category":           filter.Categories,
			"policy":             filter.Policies,
			"rule":               filter.Rules,
			"resource_namespace": filter.Namespaces,
			"resource_kind":      filter.Kinds,
			"resource_api":       filter.ResourceAPIs,
			"resource_name":      filter.Resources,
			"result":             filter.Status,
			"severity":           filter.Severities,
		}).
		Scoped(namespaced).
		FilterValue(`r.resource_id`, filter.ResourceID).
		ResultSearch(filter.Search).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "r").
		GetQuery().
		Count(ctx))
}

func (s *Store) FetchResultsWithoutResource(ctx context.Context, filter Filter, pagination Pagination) ([]PolicyReportResult, error) {
	results := make([]PolicyReportResult, 0)

	err := FromQuery(s.db.NewSelect().Model(&results)).
		FilterMap(map[string][]string{
			"source":   filter.Sources,
			"category": filter.Categories,
			"policy":   filter.Policies,
			"rule":     filter.Rules,
			"result":   filter.Status,
			"severity": filter.Severities,
		}).
		WithEmpty("resource_name").
		ResultSearch(filter.Search).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "r").
		Pagination(pagination).
		Scan(ctx)

	return results, err
}

func (s *Store) CountResultsWithoutResource(ctx context.Context, filter Filter) (int, error) {
	return CountResult(FromQuery(s.db.NewSelect().Model((*PolicyReportResult)(nil))).
		FilterMap(map[string][]string{
			"source":   filter.Sources,
			"category": filter.Categories,
			"policy":   filter.Policies,
			"rule":     filter.Rules,
			"result":   filter.Status,
			"severity": filter.Severities,
		}).
		WithEmpty("resource_name").
		ResultSearch(filter.Search).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "r").
		GetQuery().
		Count(ctx))
}

func (s *Store) UseResources(ctx context.Context, source string, filter Filter) (bool, error) {
	return FromQuery(s.db.NewSelect().Model((*PolicyReportResult)(nil))).
		FilterValue("source", source).
		FilterMap(map[string][]string{
			"category": filter.Categories,
			"policy":   filter.Policies,
			"rule":     filter.Rules,
		}).
		WithNotEmpty("resource_name").
		ResultSearch(filter.Search).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "r").
		GetQuery().
		Exists(ctx)
}

func (s *Store) FetchClusterStatusCounts(ctx context.Context, source string, filter Filter) ([]StatusCount, error) {
	results := make([]StatusCount, 0)

	err := FromQuery(s.db.
		NewSelect().
		TableExpr("policy_report_filter as f").
		ColumnExpr("SUM(f.count) as count, f.result as status")).
		FilterMap(map[string][]string{
			"category":      filter.Categories,
			"policy":        filter.Policies,
			"resource_kind": filter.Kinds,
			"resource_api":  filter.ResourceAPIs,
		}).
		FilterValue("f.source", source).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "f").
		ClusterScope().
		Group("status").
		Scan(ctx, &results)

	return results, err
}

func (s *Store) FetchClusterSeverityCounts(ctx context.Context, source string, filter Filter) ([]SeverityCount, error) {
	results := make([]SeverityCount, 0)

	err := FromQuery(s.db.
		NewSelect().
		TableExpr("policy_report_filter as f").
		ColumnExpr("SUM(f.count) as count, f.severity")).
		FilterMap(map[string][]string{
			"category":      filter.Categories,
			"policy":        filter.Policies,
			"resource_kind": filter.Kinds,
			"resource_api":  filter.ResourceAPIs,
		}).
		FilterValue("f.source", source).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "f").
		ClusterScope().
		Group("f.severity").
		Scan(ctx, &results)

	return results, err
}

func (s *Store) FetchNamespaceStatusCounts(ctx context.Context, source string, filter Filter) ([]StatusCount, error) {
	results := make([]StatusCount, 0)

	err := FromQuery(s.db.
		NewSelect().
		TableExpr("policy_report_filter as f").
		ColumnExpr("f.resource_namespace, SUM(f.count) as count, f.result as status")).
		FilterMap(map[string][]string{
			"f.category":           filter.Categories,
			"f.resource_kind":      filter.Kinds,
			"f.resource_api":       filter.ResourceAPIs,
			"f.resource_namespace": filter.Namespaces,
			"f.policy":             filter.Policies,
			"f.result":             filter.Status,
		}).
		FilterValue("f.source", source).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "f").
		NamespaceScope().
		Group("f.resource_namespace", "f.result").
		Order("f.resource_namespace ASC", "f.result ASC").
		Scan(ctx, &results)

	return results, err
}

func (s *Store) FetchNamespaceSeverityCounts(ctx context.Context, source string, filter Filter) ([]SeverityCount, error) {
	results := make([]SeverityCount, 0)

	err := FromQuery(s.db.
		NewSelect().
		TableExpr("policy_report_filter as f").
		ColumnExpr("f.resource_namespace, SUM(f.count) as count, f.severity")).
		FilterMap(map[string][]string{
			"f.category":           filter.Categories,
			"f.resource_kind":      filter.Kinds,
			"f.resource_api":       filter.ResourceAPIs,
			"f.resource_namespace": filter.Namespaces,
			"f.policy":             filter.Policies,
			"f.severity":           filter.Severities,
		}).
		FilterValue("f.source", source).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "f").
		NamespaceScope().
		Group("f.resource_namespace", "f.severity").
		Order("f.resource_namespace ASC", "f.severity ASC").
		Scan(ctx, &results)

	return results, err
}

func (s *Store) FetchTotalStatusCounts(ctx context.Context, source string, filter Filter) ([]StatusCount, error) {
	results := make([]StatusCount, 0)

	err := FromQuery(s.db.
		NewSelect().
		TableExpr("policy_report_filter as f").
		ColumnExpr("SUM(f.count) as count, f.result AS status")).
		FilterMap(map[string][]string{
			"category":      filter.Categories,
			"policy":        filter.Policies,
			"resource_kind": filter.Kinds,
			"resource_api":  filter.ResourceAPIs,
		}).
		FilterValue("f.source", source).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "f").
		Group("f.result").
		Scan(ctx, &results)

	return results, err
}

func (s *Store) FetchTotalSeverityCounts(ctx context.Context, source string, filter Filter) ([]SeverityCount, error) {
	results := make([]SeverityCount, 0)

	err := FromQuery(s.db.
		NewSelect().
		TableExpr("policy_report_filter as f").
		ColumnExpr("SUM(f.count) as count, f.severity")).
		FilterMap(map[string][]string{
			"category":      filter.Categories,
			"policy":        filter.Policies,
			"resource_kind": filter.Kinds,
			"resource_api":  filter.ResourceAPIs,
		}).
		FilterValue("f.source", source).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "f").
		Group("severity").
		Scan(ctx, &results)

	return results, err
}

func (s *Store) FetchNamespaceKinds(ctx context.Context, filter Filter) ([]string, error) {
	list := make([]string, 0)

	err := NewFilterQuery(s.db, "resource_kind").
		FilterMap(map[string][]string{
			"f.source":             filter.Sources,
			"f.category":           filter.Categories,
			"f.resource_namespace": filter.Namespaces,
		}).
		Exclude(filter, "f").
		FilterReportLabels(filter.ReportLabel).
		NamespaceScope().
		Scan(ctx, &list)

	return list, err
}

func (s *Store) FetchClusterKinds(ctx context.Context, filter Filter) ([]string, error) {
	list := make([]string, 0)

	err := NewFilterQuery(s.db, "resource_kind").
		FilterMap(map[string][]string{
			"f.source":   filter.Sources,
			"f.category": filter.Categories,
		}).
		Exclude(filter, "f").
		FilterReportLabels(filter.ReportLabel).
		ClusterScope().
		Scan(ctx, &list)

	return list, err
}

func (s *Store) FetchPolicies(ctx context.Context, filter Filter) ([]PolicyReportFilter, error) {
	results := make([]PolicyReportFilter, 0)

	err := FromQuery(s.db.NewSelect().Model(&results).ColumnExpr("f.severity, f.category, f.policy, f.source, f.result, SUM(f.count) as count")).
		FilterMap(map[string][]string{
			"f.source":        filter.Sources,
			"f.category":      filter.Categories,
			"f.resource_kind": filter.Kinds,
			"f.resource_api":  filter.ResourceAPIs,
		}).
		PolicySearch(filter.Search).
		Exclude(filter, "f").
		FilterReportLabels(filter.ReportLabel).
		Order("f.source ASC", "f.category ASC").
		Group("f.category", "f.policy", "f.source", "f.result", "f.severity").
		Scan(ctx)

	return results, err
}

func (s *Store) FetchFindingCounts(ctx context.Context, filter Filter) ([]StatusCount, error) {
	results := make([]StatusCount, 0)

	query := FromQuery(s.db.
		NewSelect().
		TableExpr("policy_report_filter as f").
		ColumnExpr("SUM(f.count) as count, f.result as status, f.source"))

	if filter.Namespaced {
		query.
			NamespaceScope().
			Filter("resource_namespace", filter.Namespaces)
	} else {
		query.ClusterScope()
	}

	err := query.
		FilterMap(map[string][]string{
			"source":        filter.Sources,
			"category":      filter.Categories,
			"resource_kind": filter.Kinds,
			"resource_api":  filter.ResourceAPIs,
			"policy":        filter.Policies,
			"f.result":      filter.Status,
		}).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "f").
		Group("f.source", "f.result").
		Order("f.source").
		Scan(ctx, &results)

	return results, err
}

func (s *Store) FetchSeverityFindingCounts(ctx context.Context, filter Filter) ([]SeverityCount, error) {
	results := make([]SeverityCount, 0)

	query := FromQuery(s.db.
		NewSelect().
		TableExpr("policy_report_filter as f").
		ColumnExpr("SUM(f.count) as count, f.severity, f.source"))

	if filter.Namespaced {
		query.
			NamespaceScope().
			Filter("resource_namespace", filter.Namespaces)
	} else {
		query.FilterOptionalNamespaces(filter.Namespaces)
	}

	err := query.
		FilterMap(map[string][]string{
			"source":        filter.Sources,
			"category":      filter.Categories,
			"resource_kind": filter.Kinds,
			"resource_api":  filter.ResourceAPIs,
			"policy":        filter.Policies,
			"severity":      filter.Severities,
		}).
		FilterReportLabels(filter.ReportLabel).
		Exclude(filter, "f").
		Group("f.source", "f.severity").
		Order("f.source").
		Scan(ctx, &results)

	return results, err
}

/////////////////////////
/// Lifecycle Methods ///
/////////////////////////

func (s *Store) CreateSchemas(ctx context.Context) error {
	return createSchemas(ctx, s.db)
}

func createSchemas(ctx context.Context, db bun.IDB) error {
	if db.Dialect().Name() == dialect.SQLite {
		if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
			return err
		}
	}

	_, err := db.
		NewCreateTable().
		IfNotExists().
		Model((*Config)(nil)).
		Exec(ctx)
	logOnError("create policy_report_config table", err)
	if err != nil {
		return err
	}

	_, err = db.
		NewCreateTable().
		IfNotExists().
		Model((*PolicyReport)(nil)).
		Exec(ctx)
	logOnError("create policy_report table", err)
	if err != nil {
		return err
	}

	_, err = db.
		NewCreateTable().
		IfNotExists().
		Model((*PolicyReportResult)(nil)).
		ForeignKey(`(policy_report_id) REFERENCES policy_report(id) ON DELETE CASCADE`).
		Exec(ctx)
	logOnError("create policy_report_result table", err)
	if err != nil {
		return err
	}

	_, err = db.
		NewCreateTable().
		IfNotExists().
		Model((*PolicyReportFilter)(nil)).
		ForeignKey(`(policy_report_id) REFERENCES policy_report(id) ON DELETE CASCADE`).
		Exec(ctx)
	logOnError("create policy_report_filter table", err)
	if err != nil {
		return err
	}

	_, err = db.
		NewCreateTable().
		IfNotExists().
		Model((*ResourceResult)(nil)).
		ForeignKey(`(policy_report_id) REFERENCES policy_report(id) ON DELETE CASCADE`).
		Exec(ctx)
	logOnError("create policy_report_resource table", err)
	if err != nil {
		return err
	}

	return err
}

func (s *Store) DropSchema(ctx context.Context) error {
	return dropSchema(ctx, s.db)
}

// dropSchema removes the child tables before their parent. PostgreSQL rejects
// dropping policy_report while policy_report_resource still references it (and
// would leave a partial schema behind), and no backend needs CASCADE here.
func dropSchema(ctx context.Context, db bun.IDB) error {
	drops := []struct {
		model     any
		operation string
	}{
		{(*ResourceResult)(nil), "drop policy_report_resource table"},
		{(*PolicyReportResult)(nil), "drop policy_report_result table"},
		{(*PolicyReportFilter)(nil), "drop policy_report_filter table"},
		{(*PolicyReport)(nil), "drop policy_report table"},
		{(*Config)(nil), "drop policy_report_config table"},
	}

	for _, drop := range drops {
		_, err := db.NewDropTable().IfExists().Model(drop.model).Exec(ctx)
		logOnError(drop.operation, err)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) Add(ctx context.Context, report openreports.ReportInterface) error {
	return add(ctx, s.db, report)
}

func add(ctx context.Context, db bun.IDB, report openreports.ReportInterface) error {
	_, err := db.NewInsert().Model(MapPolicyReport(report)).Exec(ctx)
	if err != nil {
		zap.L().Error("failed to persist policy report", zap.Error(err))
		errorMetric.With(prometheus.Labels{"operation": "INSERT", "table": "policy_report", "reason": mapReason(err)}).Inc()
		return err
	}

	filters := chunkSlice(MapPolicyReportFilter(report), 50)
	for _, list := range filters {
		_, err = db.NewInsert().Ignore().Model(&list).Exec(ctx)
		if err != nil {
			zap.L().Error("failed to bulk import policy report filter", zap.Error(err))
			errorMetric.With(prometheus.Labels{"operation": "INSERT", "table": "policy_report_filter", "reason": mapReason(err)}).Inc()
			return err
		}
	}

	resources := chunkSlice(MapPolicyReportResource(report), 50)
	for _, list := range resources {
		_, err = db.NewInsert().Model(&list).Exec(ctx)
		if err != nil {
			zap.L().Error("failed to bulk import policy report resources", zap.Error(err))
			errorMetric.With(prometheus.Labels{"operation": "INSERT", "table": "policy_report_resource", "reason": mapReason(err)}).Inc()
			return err
		}
	}

	results := chunkSlice(MapPolicyReportResults(report), 50)
	for _, list := range results {
		_, err = db.NewInsert().Ignore().Model(&list).Exec(ctx)
		if err != nil {
			zap.L().Error("failed to bulk import policy report results", zap.Error(err))
			errorMetric.With(prometheus.Labels{"operation": "INSERT", "table": "policy_report_result", "reason": mapReason(err)}).Inc()
			return err
		}
	}

	return err
}

func (s *Store) Update(ctx context.Context, report openreports.ReportInterface) error {
	// Replace the report in one transaction, so that a failed insert keeps the
	// previous report and readers never see part of the new one.
	return s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := remove(ctx, tx, report.GetID()); err != nil {
			return err
		}

		return add(ctx, tx, report)
	})
}

func (s *Store) Remove(ctx context.Context, id string) error {
	return remove(ctx, s.db, id)
}

func remove(ctx context.Context, db bun.IDB, id string) error {
	_, err := db.NewDelete().Model((*PolicyReport)(nil)).Where("id = ?", id).Exec(ctx)
	if err != nil {
		zap.L().Error("failed to remove previous policy report", zap.Error(err))
		errorMetric.With(prometheus.Labels{"operation": "DELETE", "table": "policy_report", "reason": mapReason(err)}).Inc()
	}

	return err
}

// PostgreSQL clears the whole cache in one atomic statement, while the parent
// DELETE scans and cascades through every row of all four tables.
const postgresCleanUpQuery = "TRUNCATE TABLE ONLY policy_report, ONLY policy_report_resource, ONLY policy_report_result, ONLY policy_report_filter RESTRICT"

func (s *Store) CleanUp(ctx context.Context) error {
	return cleanUp(ctx, s.db)
}

func cleanUp(ctx context.Context, db bun.IDB) error {
	operation := "DELETE"
	var err error
	if db.Dialect().Name() == dialect.PG {
		operation = "TRUNCATE"
		_, err = db.ExecContext(ctx, postgresCleanUpQuery)
	} else {
		_, err = db.NewDelete().Model((*PolicyReport)(nil)).Where("id is not null").Exec(ctx)
	}
	if err != nil {
		zap.L().Error("failed to remove policy reports", zap.Error(err))
		errorMetric.With(prometheus.Labels{"operation": operation, "table": "policy_report", "reason": mapReason(err)}).Inc()
	}

	return err
}

func (s *Store) Get(ctx context.Context, id string) (openreports.ReportInterface, error) {
	polr := &PolicyReport{}

	err := s.db.NewSelect().Model(polr).Where("id = ?", id).Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, err
	} else if err != nil {
		zap.L().Error("failed to load policy report", zap.Error(err))
		return nil, err
	}

	results, err := s.fetchResults(ctx, id)
	if err != nil {
		zap.L().Error("failed to load policy report results", zap.Error(err))
		return nil, err
	}

	return &openreports.ReportAdapter{
		Report: &v1alpha1.Report{
			ObjectMeta: v1.ObjectMeta{
				Name:              polr.Name,
				Namespace:         polr.Namespace,
				CreationTimestamp: v1.NewTime(time.Unix(polr.Created, 0)),
				Labels:            polr.Labels,
			},
			Summary: v1alpha1.ReportSummary{
				Skip:  polr.Skip,
				Pass:  polr.Pass,
				Warn:  polr.Warn,
				Fail:  polr.Fail,
				Error: polr.Error,
			},
			Results: results,
		},
	}, nil
}

func (s *Store) SQLDialect() dialect.Name {
	return s.db.Dialect().Name()
}

func (s *Store) IsSQLite() bool {
	return s.db.Dialect().Name() == dialect.SQLite
}

func (s *Store) fetchResults(ctx context.Context, id string) ([]v1alpha1.ReportResult, error) {
	polr := []*PolicyReportResult{}

	err := s.db.NewSelect().Model(&polr).Where("policy_report_id = ?", id).Scan(ctx)
	if err != nil {
		zap.L().Error("failed to load policy report results", zap.Error(err))
		return nil, err
	}

	list := make([]v1alpha1.ReportResult, 0, len(polr))
	for _, result := range polr {
		list = append(list, v1alpha1.ReportResult{
			Result:      v1alpha1.Result(result.Result),
			Severity:    v1alpha1.ResultSeverity(result.Severity),
			Policy:      result.Policy,
			Rule:        result.Rule,
			Description: result.Message,
			Source:      result.Source,
			Subjects: []corev1.ObjectReference{
				{
					APIVersion: result.Resource.APIVersion,
					Kind:       result.Resource.Kind,
					Namespace:  result.Resource.Namespace,
					Name:       result.Resource.Name,
					UID:        types.UID(result.Resource.UID),
				},
			},
			Scored:     result.Scored,
			Properties: result.Properties,
			Category:   result.Category,
			Timestamp: v1.Timestamp{
				Seconds: result.Created,
			},
		})
	}

	return list, nil
}

func (s *Store) RequireSchemaUpgrade(ctx context.Context) bool {
	if s.IsSQLite() {
		return true
	}

	upgrade, err := requireSchemaUpgrade(ctx, s.db, s.version)
	if err != nil {
		zap.L().Debug("failed to load config", zap.Error(err))
		return true
	}

	return upgrade
}

func requireSchemaUpgrade(ctx context.Context, db bun.IDB, version string) (bool, error) {
	config := Config{}

	if err := db.NewSelect().Model(&config).Where("id = ?", 1).Scan(ctx); err != nil {
		return false, err
	}

	return config.Version != version, nil
}

func (s *Store) PersistSchemaVersion(ctx context.Context) error {
	return persistSchemaVersion(ctx, s.db, s.version)
}

func persistSchemaVersion(ctx context.Context, db bun.IDB, version string) error {
	config := Config{
		Version: version,
	}

	_, err := db.NewInsert().Model(&config).Exec(ctx)
	if err != nil {
		zap.L().Error("failed to persist database version", zap.Error(err))
		return err
	}

	return nil
}

func (s *Store) PrepareDatabase(ctx context.Context) error {
	zap.L().Debug("preparing database")

	if s.db.Dialect().Name() == dialect.PG {
		return s.preparePostgresDatabase(ctx)
	}

	if s.RequireSchemaUpgrade(ctx) {
		zap.L().Debug("database schema upgrade started")
		if err := s.DropSchema(ctx); err != nil {
			return err
		}

		if err := s.CreateSchemas(ctx); err != nil {
			return err
		}

		if err := s.PersistSchemaVersion(ctx); err != nil {
			return err
		}
	}

	return s.CleanUp(ctx)
}

const (
	// postgresPrepareLockClass scopes the advisory lock to database preparation.
	postgresPrepareLockClass int64 = 0x70523031 // "pR01"
)

var postgresTargetTables = []string{
	"policy_report_config",
	"policy_report",
	"policy_report_resource",
	"policy_report_result",
	"policy_report_filter",
}

// postgresPrepareLockKey packs the schema namespace OID and a purpose constant
// into one bigint advisory lock key. OIDs are uint32, so shifting them into the
// high bits keeps the key positive and unique per schema.
func postgresPrepareLockKey(namespaceOID int64) int64 {
	return namespaceOID<<31 | postgresPrepareLockClass
}

// preparePostgresDatabase prepares the schema in one read committed transaction.
// The transaction-scoped advisory lock serializes cooperating preparers of the
// same schema, the search path guard fails closed before any destructive
// statement, and a failure rolls the whole preparation back so no partial
// schema is left behind. The lock cannot coordinate older binaries that do not
// take it, and it does not stop other instances from clearing their caches.
func (s *Store) preparePostgresDatabase(ctx context.Context) error {
	return s.db.RunInTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, func(ctx context.Context, tx bun.Tx) error {
		if err := lockPostgresPrepare(ctx, tx); err != nil {
			return err
		}

		rebuild, err := postgresSchemaUpgradeRequired(ctx, tx, s.version)
		if err != nil {
			return err
		}

		if rebuild {
			zap.L().Debug("database schema upgrade started")
			if err := dropSchema(ctx, tx); err != nil {
				return err
			}

			if err := createSchemas(ctx, tx); err != nil {
				return err
			}

			if err := persistSchemaVersion(ctx, tx, s.version); err != nil {
				return err
			}
		}

		// TRUNCATE keeps an exclusive lock on the cache tables until commit, so
		// the index build below cannot race writers and a failure rolls the
		// truncate back.
		if err := cleanUp(ctx, tx); err != nil {
			return err
		}

		if err := ensurePostgresIndexes(ctx, tx); err != nil {
			return err
		}

		return nil
	})
}

func lockPostgresPrepare(ctx context.Context, db bun.IDB) error {
	var schema sql.NullString
	var namespaceOID sql.NullInt64
	if err := db.QueryRowContext(ctx, "SELECT current_schema(), (SELECT oid FROM pg_namespace WHERE nspname = current_schema())").Scan(&schema, &namespaceOID); err != nil {
		return fmt.Errorf("resolve current schema: %w", err)
	}
	if !schema.Valid || schema.String == "" {
		return errors.New("resolve current schema: search_path resolves to no schema")
	}
	if !namespaceOID.Valid {
		return fmt.Errorf("resolve current schema: schema %q has no namespace oid", schema.String)
	}

	if _, err := db.ExecContext(ctx, "SELECT pg_advisory_xact_lock(?)", postgresPrepareLockKey(namespaceOID.Int64)); err != nil {
		return fmt.Errorf("lock database schema %q: %w", schema.String, err)
	}

	return guardPostgresSchema(ctx, db, schema.String, namespaceOID.Int64)
}

const postgresSchemaGuardQuery = `SELECT current_schema(),
	pg_my_temp_schema()::bigint,
	(SELECT oid FROM pg_namespace WHERE nspname = current_schema())`

// guardPostgresSchema rejects a session whose search_path could resolve the
// cache tables outside the schema locked by the transaction. A multi-schema
// path is fine as long as every existing cache table still resolves to the
// locked schema.
func guardPostgresSchema(ctx context.Context, db bun.IDB, schema string, namespaceOID int64) error {
	var current sql.NullString
	var tempNamespace int64
	var currentNamespace sql.NullInt64
	if err := db.QueryRowContext(ctx, postgresSchemaGuardQuery).Scan(&current, &tempNamespace, &currentNamespace); err != nil {
		return fmt.Errorf("inspect search_path: %w", err)
	}
	if tempNamespace != 0 {
		return fmt.Errorf("search_path uses temporary schema %d, which is searched before %q", tempNamespace, schema)
	}
	if !current.Valid || current.String != schema {
		return fmt.Errorf("current schema changed from %q to %q while acquiring the prepare lock", schema, current.String)
	}
	if !currentNamespace.Valid || currentNamespace.Int64 != namespaceOID {
		return fmt.Errorf("database schema %q changed while acquiring the prepare lock", schema)
	}

	for _, table := range postgresTargetTables {
		var resolved string
		err := db.QueryRowContext(ctx, "SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = to_regclass(?)", table).Scan(&resolved)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("resolve table %q: %w", table, err)
		}
		if resolved != schema {
			return fmt.Errorf("table %q resolves to schema %q outside current schema %q", table, resolved, schema)
		}
	}

	return nil
}

// postgresSchemaUpgradeRequired reports whether the schema must be rebuilt. A
// missing config table or missing version row means a fresh or incomplete
// schema, while any other read error aborts the preparation.
func postgresSchemaUpgradeRequired(ctx context.Context, db bun.IDB, version string) (bool, error) {
	var exists bool
	if err := db.QueryRowContext(ctx, "SELECT to_regclass('policy_report_config') IS NOT NULL").Scan(&exists); err != nil {
		return false, fmt.Errorf("check config table: %w", err)
	}
	if !exists {
		return true, nil
	}

	var persisted string
	err := db.QueryRowContext(ctx, "SELECT version FROM policy_report_config WHERE id = 1").Scan(&persisted)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read config version: %w", err)
	}

	return persisted != version, nil
}

type postgresChildIndex struct {
	table string
	name  string
}

var postgresChildIndexes = []postgresChildIndex{
	{table: "policy_report_resource", name: "policy_report_resource_policy_report_id_idx"},
	{table: "policy_report_result", name: "policy_report_result_policy_report_id_idx"},
	{table: "policy_report_filter", name: "policy_report_filter_policy_report_id_idx"},
}

// postgresSuitableIndexQuery finds an existing index that a default lookup by
// policy_report_id can use: a live, valid, ready, non-partial btree whose first
// key column is policy_report_id with the default operator class and the
// column's collation. Trailing key columns or expressions are allowed.
const postgresSuitableIndexQuery = `SELECT c.relname
FROM pg_index i
JOIN pg_class c ON c.oid = i.indexrelid
JOIN pg_class t ON t.oid = i.indrelid
JOIN pg_namespace n ON n.oid = t.relnamespace
JOIN pg_attribute a ON a.attrelid = t.oid AND a.attname = 'policy_report_id'
JOIN pg_am am ON am.oid = c.relam
JOIN pg_opclass opc ON opc.oid = i.indclass[0]
WHERE n.nspname = current_schema()
	AND t.relname = ?
	AND i.indisvalid
	AND i.indisready
	AND i.indislive
	AND i.indpred IS NULL
	AND am.amname = 'btree'
	AND i.indkey[0] = a.attnum
	AND i.indcollation[0] = a.attcollation
	AND opc.opcmethod = am.oid
	AND opc.opcdefault
	AND (opc.opcintype = a.atttypid OR EXISTS (
		SELECT 1
		FROM pg_cast ct
		WHERE ct.castsource = a.atttypid
			AND ct.casttarget = opc.opcintype
			AND ct.castmethod = 'b'
	))
ORDER BY c.relname`

func ensurePostgresIndexes(ctx context.Context, db bun.IDB) error {
	for _, index := range postgresChildIndexes {
		if err := ensurePostgresIndex(ctx, db, index); err != nil {
			return err
		}
	}

	return nil
}

// ensurePostgresIndex reuses a suitable index under any name. When the expected
// name is taken by an incompatible relation it fails instead of silently
// skipping (IF NOT EXISTS) or dropping an operator-created index.
func ensurePostgresIndex(ctx context.Context, db bun.IDB, index postgresChildIndex) error {
	suitable, err := postgresSuitableIndexNames(ctx, db, index.table)
	if err != nil {
		return err
	}
	if len(suitable) > 0 {
		return nil
	}

	var relkind string
	err = db.QueryRowContext(ctx, "SELECT c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND c.relname = ?", index.name).Scan(&relkind)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("inspect relation name %q: %w", index.name, err)
	}
	if err == nil {
		if relkind == "i" {
			return fmt.Errorf("index %q exists but is not a usable btree index leading with policy_report_id", index.name)
		}

		return fmt.Errorf("relation name %q is already used by a %q relation", index.name, relkind)
	}

	if _, err := db.NewCreateIndex().Index(index.name).Table(index.table).Column("policy_report_id").Exec(ctx); err != nil {
		return wrapPostgresIndexError(index, err)
	}

	return nil
}

func wrapPostgresIndexError(index postgresChildIndex, err error) error {
	var pgErr pgdriver.Error
	if errors.As(err, &pgErr) && pgErr.Field('C') == "42501" {
		return fmt.Errorf("create index %q on %s: PostgreSQL requires ownership of the table to create the index automatically: %w", index.name, index.table, err)
	}

	return fmt.Errorf("create index %q on %s: %w", index.name, index.table, err)
}

func postgresSuitableIndexNames(ctx context.Context, db bun.IDB, table string) ([]string, error) {
	rows, err := db.QueryContext(ctx, postgresSuitableIndexQuery, table)
	if err != nil {
		return nil, fmt.Errorf("inspect indexes on %s: %w", table, err)
	}
	defer rows.Close()

	names := make([]string, 0, 1)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("inspect indexes on %s: %w", table, err)
		}
		names = append(names, name)
	}

	return names, rows.Err()
}

func NewStore(db *bun.DB, version string) (*Store, error) {
	if db == nil {
		return nil, errors.New("missing database connection")
	}

	s := &Store{
		db:      db,
		version: version,
	}

	return s, nil
}

func NewSQLiteDB(dbFile string) (*bun.DB, error) {
	sqldb, err := createSQLiteDB(dbFile)
	if err != nil {
		return nil, err
	}

	return bun.NewDB(sqldb, sqlitedialect.New()), nil
}

func createSQLiteDB(dbFile string) (*sql.DB, error) {
	os.Remove(dbFile)
	file, err := os.Create(dbFile)
	if err != nil {
		return nil, err
	}
	file.Close()

	db, err := sql.Open("sqlite3", dbFile+"?cache=shared")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	return db, nil
}

func chunkSlice[K interface{}](slice []K, chunkSize int) [][]K {
	var chunks [][]K
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize

		if end > len(slice) {
			end = len(slice)
		}

		chunks = append(chunks, slice[i:end])
	}

	return chunks
}

func logOnError(operation string, err error) {
	if err == nil {
		return
	}

	zap.L().Error("failed to execute db operatopn", zap.String("operatopm", operation), zap.Error(err))
}
