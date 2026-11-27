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

// dropSchema drops the child tables before their parent: PostgreSQL rejects
// dropping policy_report while policy_report_resource still references it.
func dropSchema(ctx context.Context, db bun.IDB) error {
	_, err := db.NewDropTable().
		IfExists().
		Model((*PolicyReportFilter)(nil)).
		Exec(ctx)
	logOnError("drop policy_report_filter table", err)
	if err != nil {
		return err
	}

	_, err = db.NewDropTable().
		IfExists().
		Model((*PolicyReportResult)(nil)).
		Exec(ctx)
	logOnError("drop policy_report_result table", err)
	if err != nil {
		return err
	}

	_, err = db.NewDropTable().
		IfExists().
		Model((*ResourceResult)(nil)).
		Exec(ctx)
	logOnError("drop policy_report_resource table", err)
	if err != nil {
		return err
	}

	_, err = db.NewDropTable().
		IfExists().
		Model((*PolicyReport)(nil)).
		Exec(ctx)
	logOnError("drop policy_report table", err)
	if err != nil {
		return err
	}

	_, err = db.NewDropTable().
		IfExists().
		Model((*Config)(nil)).
		Exec(ctx)
	logOnError("drop policy_report_config table", err)
	if err != nil {
		return err
	}

	return err
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

func (s *Store) CleanUp(ctx context.Context) error {
	return cleanUp(ctx, s.db)
}

func cleanUp(ctx context.Context, db bun.IDB) error {
	_, err := db.NewDelete().Model((*PolicyReport)(nil)).Where("id is not null").Exec(ctx)
	if err != nil {
		zap.L().Error("failed to remove policy reports", zap.Error(err))
		errorMetric.With(prometheus.Labels{"operation": "DELETE", "table": "policy_report", "reason": mapReason(err)}).Inc()
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

	config := Config{}

	err := s.db.NewSelect().Model(&config).Where("id = ?", 1).Scan(ctx)
	if err != nil {
		zap.L().Debug("failed to load config", zap.Error(err))
		return true
	}

	return config.Version != s.version
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
		return s.preparePostgres(ctx)
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

// prepareLockKey is the advisory lock taken while preparing PostgreSQL. Advisory
// locks are scoped to the current database, so instances using the same database
// serialize even across schemas; older binaries do not take the lock. See
// docs/POSTGRES_INDEXES.md.
const prepareLockKey int64 = 0x706f6c696379 // "policy"

// policyReportIndexTables are the child tables whose cascade deletes need an
// index on policy_report_id; the foreign keys themselves do not create one.
var policyReportIndexTables = []string{"policy_report_filter", "policy_report_result", "policy_report_resource"}

// postgresTargetRelations are the tables the lifecycle creates, drops and
// deletes with unqualified statements.
var postgresTargetRelations = []string{
	"policy_report_config", "policy_report", "policy_report_result", "policy_report_filter", "policy_report_resource",
}

// guardPostgresSchema fails closed before any DDL or delete: unqualified
// statements follow search_path, so every existing target table must resolve
// into current_schema() and no temporary schema may shadow it.
func guardPostgresSchema(ctx context.Context, db bun.IDB) error {
	var tempSchema int64
	var current sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT pg_my_temp_schema()::bigint, current_schema()").Scan(&tempSchema, &current); err != nil {
		return fmt.Errorf("inspect search_path: %w", err)
	}
	if !current.Valid || current.String == "" {
		return errors.New("search_path resolves to no current schema")
	}
	if tempSchema != 0 {
		return errors.New("search_path includes a temporary schema")
	}

	for _, relation := range postgresTargetRelations {
		var resolved string
		err := db.QueryRowContext(ctx, "SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = to_regclass(?)", relation).Scan(&resolved)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("resolve %s through search_path: %w", relation, err)
		}
		if resolved != current.String {
			return fmt.Errorf("search_path resolves %s to schema %q instead of %q", relation, resolved, current.String)
		}
	}

	return nil
}

// preparePostgres prepares PostgreSQL in one READ COMMITTED transaction: rebuild,
// indexes and cleanup either all commit or leave the previous schema and reports
// untouched. READ COMMITTED is explicit so a repeatable read server default
// cannot hide a version committed while waiting for the lock.
func (s *Store) preparePostgres(ctx context.Context) error {
	return s.db.RunInTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(?)", prepareLockKey); err != nil {
			return fmt.Errorf("lock database preparation: %w", err)
		}

		if err := guardPostgresSchema(ctx, tx); err != nil {
			return err
		}

		upgrade, err := requiresSchemaUpgrade(ctx, tx, s.version)
		if err != nil {
			return err
		}

		if upgrade {
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

		// Create indexes before the cleanup delete, which needs them most.
		if err := ensurePolicyReportIndexes(ctx, tx); err != nil {
			return err
		}

		return cleanUp(ctx, tx)
	})
}

// requiresSchemaUpgrade reports whether the schema must be rebuilt. A missing
// config table or version row is a fresh or incomplete database; any other read
// failure aborts preparation so a transient error cannot drop stored reports.
func requiresSchemaUpgrade(ctx context.Context, db bun.IDB, version string) (bool, error) {
	var exists bool
	if err := db.NewRaw("SELECT to_regclass('policy_report_config') IS NOT NULL").Scan(ctx, &exists); err != nil {
		return false, fmt.Errorf("check policy_report_config table: %w", err)
	}
	if !exists {
		return true, nil
	}

	config := Config{}
	err := db.NewSelect().Model(&config).Where("id = ?", 1).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read schema version: %w", err)
	}

	return config.Version != version, nil
}

// ensurePolicyReportIndexes reuses a usable index or creates the reserved one,
// before the cleanup delete that needs it. Existing indexes are never dropped.
// Large installations should prebuild the index: see docs/POSTGRES_INDEXES.md.
func ensurePolicyReportIndexes(ctx context.Context, db bun.IDB) error {
	for _, table := range policyReportIndexTables {
		var usable bool
		if err := db.NewRaw(policyReportIndexQuery, table).Scan(ctx, &usable); err != nil {
			return fmt.Errorf("inspect indexes on %s: %w", table, err)
		}
		if usable {
			continue
		}

		name := table + "_policy_report_id_idx"
		if _, err := db.NewCreateIndex().Index(name).Table(table).Column("policy_report_id").Exec(ctx); err != nil {
			return fmt.Errorf("create index %s on %s: %w (see docs/POSTGRES_INDEXES.md)", name, table, err)
		}
	}

	return nil
}

// policyReportIndexQuery reports whether the table already has an index usable
// for policy_report_id lookups and cascade deletes.
const policyReportIndexQuery = `
SELECT EXISTS (
	SELECT 1
	FROM pg_index i
	JOIN pg_class ic ON ic.oid = i.indexrelid
	JOIN pg_am am ON am.oid = ic.relam
	JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
	WHERE i.indrelid = ?::regclass
		AND i.indisvalid
		AND i.indisready
		AND i.indislive
		AND i.indpred IS NULL
		AND am.amname = 'btree'
		AND a.attname = 'policy_report_id'
		AND i.indcollation[0] = a.attcollation
)`

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
