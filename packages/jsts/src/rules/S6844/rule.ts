/*
 * SonarQube JavaScript Plugin
 * Copyright (C) 2011-2023 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
// https://sonarsource.github.io/rspec/#/rspec/S6844/javascript

import { rules as jsxA11yRules } from 'eslint-plugin-jsx-a11y';
import { interceptReport } from '../helpers';

const anchorIsValid = jsxA11yRules['anchor-is-valid'];

export const rule = interceptReport(anchorIsValid, (context, reportDescriptor) => {
  const descriptor = reportDescriptor as any;
  const { message } = descriptor;
  descriptor.message = message.substring(0, message.indexOf(' Learn'));
  context.report(descriptor);
});
