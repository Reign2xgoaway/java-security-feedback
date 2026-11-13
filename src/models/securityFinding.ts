export interface SecurityFinding {
  ruleId: string;
  title: string;
  message: string;
  filePath: string;
  startLine: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  affectedApi: string;
}
